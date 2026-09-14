# M19b: the frozen benchmark manifest

Generated 2026-09-14T00:23:38.270692+00:00 at `49c0980`. Manifest hash `0ced14fb387c7752fe1435c876e19fbe4a8bfd3f52a830049844c31718143263`; benchmark hash `e381e387db4c5d56dfd067f7391b6e9c698f4d895bc42f73c4e6d9e31fda18b6` (the manifest hash covers the pinned inputs `run_arm` checks -- corpus, case, findings, evidence, telemetry; the benchmark hash covers those *and* every audit, link and rubric on this page).

Every number below is MEASURED: each corpus was loaded through the pipeline's own adapters, hunted, triaged and correlated exactly as `scripts/m19_ablation.py` does, and each case's necessity entry was produced by `ath.evaluation.necessity.audit_case`, which runs arm A's deterministic investigation rather than predicting it. No model was called. Every label-derived field was read by `ath.evaluation`; no adapter, rule, triage path, specialist or tool saw one.

## The selection rule

Frozen by: docs/m19b-plan.md phase 5-6 (T5), case set named by the architect in the T5 task statement; no case may be added, removed or adjusted after any measurement

The M19b benchmark case set was fixed by the architect in the T5 task statement before anything in this milestone was measured, and this script may not add or remove a case. It is: (1) `synthetic:INC-001` -- the single case `ath.evaluation.incidents.run_incident` investigates for incident INC-001 (the case with the most malicious overlap), pinned exactly as `scripts/m19_ablation.py build` pins it; the only one of M19's 22 cases that qualifies under `docs/m19b-plan.md`'s necessity test (`reports/m19b/necessity/AUDIT.md`). (2) `dedale_injected:{M1,M2,M3,M4,L1,L2}` -- every unsealed case in `reports/m19b/cases/dedale_injected/`, each loaded from its own `winlogbeat/` directory with `WinlogbeatSource` and hunted, triaged and correlated exactly as `scripts/m19_ablation.py` does; the single case each forms. `HELDOUT_H1` is excluded: it is held until the final evaluation and its answer key is sealed. (3) `flaws_cloud` -- the two identity x control_plane cases the M19b correlation link forms on real, unlabelled CloudTrail (`reports/m19b/link/BEFORE_AFTER.md`), pinned by principal and member finding ids rather than by case number, which shifts when the correlator changes. flaws.cloud is loaded exactly as `scripts/m19_ablation.py` loads it. `fixture:cloudtrail`'s new cross-domain case is deliberately excluded: it is a shipped test fixture, and a benchmark that grades a system on its own fixtures is grading its own homework.

Excluded, and why:

| excluded | reason |
| --- | --- |
| `dedale_injected:HELDOUT_H1` | held out until the final evaluation; its answer key is sealed and is not opened by this script or its tests |
| `fixture:cloudtrail` CASE-001 | a shipped test fixture. It qualifies, and it is excluded because a benchmark built on the fixtures the system is tested against grades its own homework |
| the other 20 M19 cases | none of them qualifies: `reports/m19b/necessity/AUDIT.md` measured one domain specialist eligible at every step on each |
| the other 277 flaws.cloud cases | single-domain (control_plane only) -- see the T4 audit's distribution |

## The nine cases

| case | corpus | provenance | leading rule | rules | findings | evidence ids | domains | domain specialists at step 0 | independent evidence sources | qualifies | CDER links | verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CASE-001` | `synthetic:INC-001` | synthetic | ATH-004 | ATH-001, ATH-002, ATH-003, ATH-004, ATH-005, ATH-006, ATH-007, ATH-008, ATH-009, ATH-010 | 11 | 31 | endpoint, identity, network | 3 | 3 | YES | 15 | malicious |
| `CASE-001` | `dedale_injected:M1` | real benign DEDALE background + injected attack rows (labelled) | ATH-005 | ATH-005, ATH-007 | 2 | 14 | endpoint, identity | 2 | 2 | YES | 2 | malicious |
| `CASE-001` | `dedale_injected:M2` | real benign DEDALE background + injected attack rows (labelled) | ATH-005 | ATH-005, ATH-007 | 2 | 16 | endpoint, identity | 2 | 2 | YES | 2 | malicious |
| `CASE-001` | `dedale_injected:M3` | real benign DEDALE background + injected attack rows (labelled) | ATH-005 | ATH-005, ATH-006, ATH-007 | 3 | 13 | endpoint, identity | 2 | 2 | YES | 2 | malicious |
| `CASE-001` | `dedale_injected:M4` | real benign DEDALE background + injected attack rows (labelled) | ATH-007 | ATH-005, ATH-007 | 2 | 12 | endpoint, identity | 2 | 2 | YES | 2 | malicious |
| `CASE-001` | `dedale_injected:L1` | real benign DEDALE background + injected attack rows (labelled) | ATH-005 | ATH-005, ATH-007 | 2 | 14 | endpoint, identity | 2 | 2 | YES | 2 | benign |
| `CASE-001` | `dedale_injected:L2` | real benign DEDALE background + injected attack rows (labelled) | ATH-005 | ATH-005, ATH-007 | 2 | 14 | endpoint, identity | 2 | 2 | YES | 1 | benign |
| `CASE-182` | `flaws_cloud` | real unlabelled | AWS-004 | ATH-005, AWS-004 | 2 | 66 | control_plane, identity | 2 | 2 | YES | UNAVAILABLE (unlabelled) | unknown |
| `CASE-256` | `flaws_cloud` | real unlabelled | AWS-004 | ATH-005, AWS-003, AWS-004 | 7 | 105 | control_plane, identity | 2 | 2 | YES | UNAVAILABLE (unlabelled) | unknown |

## Corpora

| corpus | process | network | logon | control | findings | cases in corpus | cases pinned | telemetry hash | load s | pipeline s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `synthetic:INC-001` | 456 | 389 | 267 | 0 | 13 | 1 | 1 | `d6e61884e3bb` | 0.0 | 0.2 |
| `dedale_injected:M1` | 267 | 0 | 36 | 0 | 2 | 1 | 1 | `662ec70e0824` | 0.0 | 0.1 |
| `dedale_injected:M2` | 292 | 0 | 38 | 0 | 2 | 1 | 1 | `8d1222961cdf` | 0.0 | 0.1 |
| `dedale_injected:M3` | 396 | 0 | 78 | 0 | 3 | 1 | 1 | `054e0e15a42d` | 0.0 | 0.1 |
| `dedale_injected:M4` | 121 | 0 | 24 | 0 | 2 | 1 | 1 | `a1aefd17a18a` | 0.0 | 0.1 |
| `dedale_injected:L1` | 430 | 0 | 81 | 0 | 2 | 1 | 1 | `9d2e871227c9` | 0.0 | 0.1 |
| `dedale_injected:L2` | 249 | 0 | 33 | 0 | 2 | 1 | 1 | `d68f234d5284` | 0.0 | 0.1 |
| `flaws_cloud` | 0 | 0 | 79424 | 1857154 | 1476 | 279 | 2 | `d124dc925e77` | 201.2 | 131.4 |

## Every case

### `synthetic:INC-001` / `CASE-001`

*Provenance:* synthetic. *Answer key:* data/raw/ground_truth.json, via ath.telemetry.loader.load_ground_truth -- the reader ath.evaluation.suite uses and the only one permitted to.

M19 pinned this same case. The M19b correlation link is asserted not to change its finding set; `build` checks that against reports/m19/ablation/MANIFEST.json rather than taking it on trust.

|  |  |
| --- | --- |
| leading rule | `ATH-004` |
| rules | `ATH-001` Office application spawned a script interpreter, `ATH-002` Encoded PowerShell command execution, `ATH-003` Script interpreter connected to an external host, `ATH-004` Possible LSASS credential access, `ATH-005` Failed logon burst followed by successful authentication, `ATH-006` Account authenticated from a host where it has no session, `ATH-007` Remote service execution (PsExec-style), `ATH-008` Bulk data staged into an archive, `ATH-009` Macro-enabled document opened via email client, `ATH-010` Sequence of discovery commands from one parent process |
| findings | `ATH-001:evt-000357`, `ATH-002:evt-000357`, `ATH-003:evt-000358`, `ATH-003:evt-000481`, `ATH-004:evt-000381`, `ATH-005:evt-000419`, `ATH-006:evt-000457`, `ATH-007:evt-000461`, `ATH-008:evt-000469`, `ATH-009:evt-000355`, `ATH-010:evt-000367` |
| evidence ids | 31 -- `evt-000355`, `evt-000357`, `evt-000358`, `evt-000362`, `evt-000367`, `evt-000370`, `evt-000374`, `evt-000380`, `evt-000381`, `evt-000399`, `evt-000419`, `evt-000421`, `evt-000422`, `evt-000425`, `evt-000427`, `evt-000429`, `evt-000431`, `evt-000432`, `evt-000433`, `evt-000437`, `evt-000438`, `evt-000439`, `evt-000440`, `evt-000442`, `evt-000444`, `evt-000454`, `evt-000457`, `evt-000461`, `evt-000469`, `evt-000481`, `evt-000486` |
| telemetry hash | `d6e61884e3bb3116fc53d20f0fbb91ab8e536650497026dc30fca7007b50950b` |
| selection | the case run_incident investigates for this incident |

**Necessity audit.** Domains with materially relevant evidence: endpoint, identity, network. Eligible at step 0: endpoint, identity, network (3 domain specialist(s)). Eligible over the whole deterministic run: attack, endpoint, identity, network. Independent evidence sources: 3 (8 endpoint, 15 identity, 8 network). Qualifies: **YES**.

*Condition 3 (what synthesis could change):* Ground truth stages 6-credential-access (LSASS dumped on PC01, endpoint), 7-brute-force (fifteen failed network logons for one account from one source, identity) and 8-lateral-movement (a service-launched shell redirected to an admin share, endpoint) are three domains' views of one transition: the endpoint rows alone cannot say the credential the shell used was guessed rather than known, the identity rows alone cannot say the guessing reached execution, and only together do they make the archive staged in stage 9-collection the property of an operator who already holds a working credential -- which is the difference between 'reset an account' and 'isolate two hosts'.

*Measured synthesis statement:* Synthesis across endpoint (what executed on the host and what started it), identity (whose credentials were used and from where), network (who the host talked to and whether the timing looks automated) can change the verdict: each domain's finding is explicable on its own, and the other domain's rows are what decide whether that explanation survives. The case carries 8 endpoint row(s), 15 identity row(s), 8 network row(s), spanning the Execution, Persistence, Stealth, Credential Access, Discovery, Lateral Movement, Collection, Command and Control tactic(s); a verdict reached from one domain alone cannot exclude the benign reading the other domain's rows rule out.

**Pre-registered CDER links.**

| link | stage transition | identity event | endpoint event | note |
| --- | --- | --- | --- | --- |
| `INC-001-LINK-01` | 7-brute-force -> 8-lateral-movement | `evt-000419` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-02` | 7-brute-force -> 8-lateral-movement | `evt-000422` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-03` | 7-brute-force -> 8-lateral-movement | `evt-000425` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-04` | 7-brute-force -> 8-lateral-movement | `evt-000427` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-05` | 7-brute-force -> 8-lateral-movement | `evt-000429` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-06` | 7-brute-force -> 8-lateral-movement | `evt-000431` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-07` | 7-brute-force -> 8-lateral-movement | `evt-000432` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-08` | 7-brute-force -> 8-lateral-movement | `evt-000433` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-09` | 7-brute-force -> 8-lateral-movement | `evt-000437` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-10` | 7-brute-force -> 8-lateral-movement | `evt-000438` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-11` | 7-brute-force -> 8-lateral-movement | `evt-000439` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-12` | 7-brute-force -> 8-lateral-movement | `evt-000440` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-13` | 7-brute-force -> 8-lateral-movement | `evt-000442` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-14` | 7-brute-force -> 8-lateral-movement | `evt-000444` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |
| `INC-001-LINK-15` | 7-brute-force -> 8-lateral-movement | `evt-000457` | `evt-000461` | repeated failed network logons for one account from one source -> command shell spawned by the service control manager, output redirected to an admin share |

**Rubric.** Stages (data/raw/ground_truth.json, scenario `intrusion`): `1-initial-access`, `2-execution`, `3-payload-download`, `4-command-and-control`, `5-discovery`, `6-credential-access`, `7-brute-force`, `8-lateral-movement`, `9-collection`, `10-exfiltration`. Verdict: **malicious**. Next action, written before any run: Isolate PC01 and the file server the svc_backup logons reached, reset svc_backup and jdoe, and block 185.220.101.47 at the perimeter -- the LSASS dump plus the guessed credential plus the staged archive is a live operator with a working credential, not three separate alerts.

### `dedale_injected:M1` / `CASE-001`

*Provenance:* real benign DEDALE background + injected attack rows (labelled). *Answer key:* reports/m19b/cases/dedale_injected/M1/labels.json, via ath.evaluation.external_labels.

Real benign DEDALE background with a labelled endpoint x identity chain injected by scripts/m19b_inject_dedale.py -- not real data about an intrusion, however real the background is.

|  |  |
| --- | --- |
| leading rule | `ATH-005` |
| rules | `ATH-005` Failed logon burst followed by successful authentication, `ATH-007` Remote service execution (PsExec-style) |
| findings | `ATH-005:wlb-logon-0000017`, `ATH-007:wlb-process-0000171` |
| evidence ids | 14 -- `wlb-logon-0000017`, `wlb-logon-0000018`, `wlb-logon-0000019`, `wlb-logon-0000023`, `wlb-logon-0000024`, `wlb-logon-0000025`, `wlb-logon-0000026`, `wlb-logon-0000027`, `wlb-logon-0000028`, `wlb-logon-0000029`, `wlb-logon-0000030`, `wlb-logon-0000031`, `wlb-logon-0000032`, `wlb-process-0000171` |
| telemetry hash | `662ec70e082491149e1035b10376c754088329e1e160be0d95b4ba191bc18967` |
| selection | the single case reports/m19b/cases/dedale_injected/M1/ forms when its winlogbeat/ directory is hunted, triaged and correlated |

**Necessity audit.** Domains with materially relevant evidence: endpoint, identity. Eligible at step 0: endpoint, identity (2 domain specialist(s)). Eligible over the whole deterministic run: attack, endpoint, identity. Independent evidence sources: 2 (1 endpoint, 13 identity). Qualifies: **YES**.

*Condition 3 (what synthesis could change):* **Verdict**: an anonymous SYSTEM shell becomes a shell whose arrival is explained by a credential that was being guessed ninety seconds earlier from a named host.

*Measured synthesis statement:* Synthesis across endpoint (what executed on the host and what started it), identity (whose credentials were used and from where) can change the verdict: each domain's finding is explicable on its own, and the other domain's rows are what decide whether that explanation survives. The case carries 1 endpoint row(s), 13 identity row(s), spanning the Execution, Persistence, Credential Access, Lateral Movement tactic(s); a verdict reached from one domain alone cannot exclude the benign reading the other domain's rows rule out.

**Pre-registered CDER links.**

| link | stage transition | identity event | endpoint event | note |
| --- | --- | --- | --- | --- |
| `M1-LINK-1` | 2-successful-logon -> 3-remote-service-execution | `wlb-logon-0000032` (`host=CLIENT9.breach.local;channel=Security;record_id=22527`) | `wlb-process-0000171` (`host=CLIENT9.breach.local;channel=Microsoft-Windows-Sysmon/Operational;record_id=863740`) | the authentication that the service-launched shell on the same host followed; the only cross-domain join this architecture can make (auth_then_exec) |
| `M1-LINK-2` | 2-successful-logon -> 4-discovery | `wlb-logon-0000032` (`host=CLIENT9.breach.local;channel=Security;record_id=22527`) | `wlb-process-0000172` (`host=CLIENT9.breach.local;channel=Microsoft-Windows-Sysmon/Operational;record_id=863741`) | the same authentication and the first command run under the shell it explains. Deliberately harder than LINK-1: no finding cites this process row, so recovering |

**Rubric.** Stages (reports/m19b/cases/dedale_injected/M1/labels.json, scenario `guessed-credential-then-remote-exec`): `1-credential-guessing`, `2-successful-logon`, `3-remote-service-execution`, `4-discovery`. Verdict: **malicious**. Next action, written before any run: Contain CLIENT7 before CLIENT9: it is the operator's foothold, it appears only in the identity rows, and resetting client9's password without it leaves whoever guessed the password free to guess the next one.

### `dedale_injected:M2` / `CASE-001`

*Provenance:* real benign DEDALE background + injected attack rows (labelled). *Answer key:* reports/m19b/cases/dedale_injected/M2/labels.json, via ath.evaluation.external_labels.

Real benign DEDALE background with a labelled endpoint x identity chain injected by scripts/m19b_inject_dedale.py -- not real data about an intrusion, however real the background is.

|  |  |
| --- | --- |
| leading rule | `ATH-005` |
| rules | `ATH-005` Failed logon burst followed by successful authentication, `ATH-007` Remote service execution (PsExec-style) |
| findings | `ATH-005:wlb-logon-0000013`, `ATH-007:wlb-process-0000235` |
| evidence ids | 16 -- `wlb-logon-0000013`, `wlb-logon-0000014`, `wlb-logon-0000015`, `wlb-logon-0000016`, `wlb-logon-0000017`, `wlb-logon-0000018`, `wlb-logon-0000019`, `wlb-logon-0000020`, `wlb-logon-0000021`, `wlb-logon-0000024`, `wlb-logon-0000026`, `wlb-logon-0000027`, `wlb-logon-0000028`, `wlb-logon-0000029`, `wlb-logon-0000030`, `wlb-process-0000235` |
| telemetry hash | `8d1222961cdf57a0f8e1c1d36b92fd7067f9f4c96ad3e9c726a051fda787b40b` |
| selection | the single case reports/m19b/cases/dedale_injected/M2/ forms when its winlogbeat/ directory is hunted, triaged and correlated |

**Necessity audit.** Domains with materially relevant evidence: endpoint, identity. Eligible at step 0: endpoint, identity (2 domain specialist(s)). Eligible over the whole deterministic run: attack, endpoint, identity. Independent evidence sources: 2 (1 endpoint, 15 identity). Qualifies: **YES**.

*Condition 3 (what synthesis could change):* The identity rows supply the *interval* -- "a credential for this host was guessed twelve minutes before this service started" is a statement neither domain can make alone, and it is the statement that decides whether the shell is an admin tool or the second stage of an intrusion.

*Measured synthesis statement:* Synthesis across endpoint (what executed on the host and what started it), identity (whose credentials were used and from where) can change the verdict: each domain's finding is explicable on its own, and the other domain's rows are what decide whether that explanation survives. The case carries 1 endpoint row(s), 15 identity row(s), spanning the Execution, Persistence, Credential Access, Lateral Movement tactic(s); a verdict reached from one domain alone cannot exclude the benign reading the other domain's rows rule out.

**Pre-registered CDER links.**

| link | stage transition | identity event | endpoint event | note |
| --- | --- | --- | --- | --- |
| `M2-LINK-1` | 2-successful-logon -> 3-remote-service-execution | `wlb-logon-0000030` (`host=CLIENT3.breach.local;channel=Security;record_id=24273`) | `wlb-process-0000235` (`host=CLIENT3.breach.local;channel=Microsoft-Windows-Sysmon/Operational;record_id=1082666`) | the authentication that the service-launched shell on the same host followed; the only cross-domain join this architecture can make (auth_then_exec) |
| `M2-LINK-2` | 2-successful-logon -> 4-discovery | `wlb-logon-0000030` (`host=CLIENT3.breach.local;channel=Security;record_id=24273`) | `wlb-process-0000236` (`host=CLIENT3.breach.local;channel=Microsoft-Windows-Sysmon/Operational;record_id=1082667`) | the same authentication and the first command run under the shell it explains. Deliberately harder than LINK-1: no finding cites this process row, so recovering |

**Rubric.** Stages (reports/m19b/cases/dedale_injected/M2/labels.json, scenario `slow-guessing-then-delayed-remote-exec`): `1-credential-guessing`, `2-successful-logon`, `3-remote-service-execution`, `4-discovery`. Verdict: **malicious**. Next action, written before any run: Reset client3's credential and then sweep the twelve minutes between the successful logon and the service-launched shell for anything else that credential touched, because at this spacing what else it reached is the open question and not what it did on the target.

### `dedale_injected:M3` / `CASE-001`

*Provenance:* real benign DEDALE background + injected attack rows (labelled). *Answer key:* reports/m19b/cases/dedale_injected/M3/labels.json, via ath.evaluation.external_labels.

Real benign DEDALE background with a labelled endpoint x identity chain injected by scripts/m19b_inject_dedale.py -- not real data about an intrusion, however real the background is.

|  |  |
| --- | --- |
| leading rule | `ATH-005` |
| rules | `ATH-005` Failed logon burst followed by successful authentication, `ATH-006` Account authenticated from a host where it has no session, `ATH-007` Remote service execution (PsExec-style) |
| findings | `ATH-005:wlb-logon-0000058`, `ATH-006:wlb-logon-0000069`, `ATH-007:wlb-process-0000334` |
| evidence ids | 13 -- `wlb-logon-0000058`, `wlb-logon-0000059`, `wlb-logon-0000060`, `wlb-logon-0000061`, `wlb-logon-0000062`, `wlb-logon-0000063`, `wlb-logon-0000064`, `wlb-logon-0000065`, `wlb-logon-0000066`, `wlb-logon-0000067`, `wlb-logon-0000068`, `wlb-logon-0000069`, `wlb-process-0000334` |
| telemetry hash | `054e0e15a42dd2c554eb8f13acd223da85d8d611bfb5b94bc1648d3cde5f164a` |
| selection | the single case reports/m19b/cases/dedale_injected/M3/ forms when its winlogbeat/ directory is hunted, triaged and correlated |

**Necessity audit.** Domains with materially relevant evidence: endpoint, identity. Eligible at step 0: endpoint, identity (2 domain specialist(s)). Eligible over the whole deterministic run: attack, endpoint, identity. Independent evidence sources: 2 (1 endpoint, 12 identity). Qualifies: **YES**.

*Condition 3 (what synthesis could change):* The endpoint rows on CLIENT9 are what turn "unusual origin" into "unusual origin, then a shell".

*Measured synthesis statement:* Synthesis across endpoint (what executed on the host and what started it), identity (whose credentials were used and from where) can change the verdict: each domain's finding is explicable on its own, and the other domain's rows are what decide whether that explanation survives. The case carries 1 endpoint row(s), 12 identity row(s), spanning the Execution, Persistence, Credential Access, Lateral Movement tactic(s); a verdict reached from one domain alone cannot exclude the benign reading the other domain's rows rule out.

**Pre-registered CDER links.**

| link | stage transition | identity event | endpoint event | note |
| --- | --- | --- | --- | --- |
| `M3-LINK-1` | 2-successful-logon -> 3-remote-service-execution | `wlb-logon-0000069` (`host=CLIENT9.breach.local;channel=Security;record_id=29163`) | `wlb-process-0000334` (`host=CLIENT9.breach.local;channel=Microsoft-Windows-Sysmon/Operational;record_id=3608676`) | the authentication that the service-launched shell on the same host followed; the only cross-domain join this architecture can make (auth_then_exec) |
| `M3-LINK-2` | 2-successful-logon -> 4-discovery | `wlb-logon-0000069` (`host=CLIENT9.breach.local;channel=Security;record_id=29163`) | `wlb-process-0000335` (`host=CLIENT9.breach.local;channel=Microsoft-Windows-Sysmon/Operational;record_id=3608677`) | the same authentication and the first command run under the shell it explains. Deliberately harder than LINK-1: no finding cites this process row, so recovering |

**Rubric.** Stages (reports/m19b/cases/dedale_injected/M3/labels.json, scenario `foreign-host-credential-use-then-remote-exec`): `1-credential-guessing`, `2-successful-logon`, `3-remote-service-execution`, `4-discovery`. Verdict: **malicious**. Next action, written before any run: Ask why CLIENT7 is authenticating as an account that has no session on it, and treat the CLIENT9 shell as the answer that turns an unusual origin into a confirmed foothold worth containing.

### `dedale_injected:M4` / `CASE-001`

*Provenance:* real benign DEDALE background + injected attack rows (labelled). *Answer key:* reports/m19b/cases/dedale_injected/M4/labels.json, via ath.evaluation.external_labels.

Real benign DEDALE background with a labelled endpoint x identity chain injected by scripts/m19b_inject_dedale.py -- not real data about an intrusion, however real the background is.

|  |  |
| --- | --- |
| leading rule | `ATH-007` |
| rules | `ATH-005` Failed logon burst followed by successful authentication, `ATH-007` Remote service execution (PsExec-style) |
| findings | `ATH-005:wlb-logon-0000011`, `ATH-007:wlb-process-0000107` |
| evidence ids | 12 -- `wlb-logon-0000011`, `wlb-logon-0000012`, `wlb-logon-0000013`, `wlb-logon-0000014`, `wlb-logon-0000015`, `wlb-logon-0000016`, `wlb-logon-0000017`, `wlb-logon-0000018`, `wlb-logon-0000019`, `wlb-logon-0000022`, `wlb-logon-0000023`, `wlb-process-0000107` |
| telemetry hash | `a1aefd17a18aeb827eeac33824d1b922846024a84143a22d7185eb1d4c19bfb7` |
| selection | the single case reports/m19b/cases/dedale_injected/M4/ forms when its winlogbeat/ directory is hunted, triaged and correlated |

**Necessity audit.** Domains with materially relevant evidence: endpoint, identity. Eligible at step 0: endpoint, identity (2 domain specialist(s)). Eligible over the whole deterministic run: attack, endpoint, identity. Independent evidence sources: 2 (1 endpoint, 11 identity). Qualifies: **YES**.

*Condition 3 (what synthesis could change):* Together they say something neither says: the operator reached execution on CLIENT3 without a logon this telemetry can show, so **the credential did not come from this burst**.

*Measured synthesis statement:* Synthesis across endpoint (what executed on the host and what started it), identity (whose credentials were used and from where) can change the verdict: each domain's finding is explicable on its own, and the other domain's rows are what decide whether that explanation survives. The case carries 1 endpoint row(s), 11 identity row(s), spanning the Execution, Credential Access, Lateral Movement tactic(s); a verdict reached from one domain alone cannot exclude the benign reading the other domain's rows rule out.

**Pre-registered CDER links.**

| link | stage transition | identity event | endpoint event | note |
| --- | --- | --- | --- | --- |
| `M4-LINK-1` | 1-credential-guessing -> 3-remote-service-execution | `wlb-logon-0000023` (`host=CLIENT3.breach.local;channel=Security;record_id=30244`) | `wlb-process-0000107` (`host=CLIENT3.breach.local;channel=Microsoft-Windows-Sysmon/Operational;record_id=4394492`) | the authentication that the service-launched shell on the same host followed; the only cross-domain join this architecture can make (auth_then_exec) |
| `M4-LINK-2` | 1-credential-guessing -> 4-discovery | `wlb-logon-0000023` (`host=CLIENT3.breach.local;channel=Security;record_id=30244`) | `wlb-process-0000108` (`host=CLIENT3.breach.local;channel=Microsoft-Windows-Sysmon/Operational;record_id=4394493`) | the same authentication and the first command run under the shell it explains. Deliberately harder than LINK-1: no finding cites this process row, so recovering |

**Rubric.** Stages (reports/m19b/cases/dedale_injected/M4/labels.json, scenario `unsuccessful-guessing-then-remote-exec`): `1-credential-guessing`, `3-remote-service-execution`, `4-discovery`. Verdict: **malicious**. Next action, written before any run: Widen collection rather than contain: execution reached CLIENT3 without a successful logon this telemetry can show, so the next action is to find the authentication that is missing -- a host already compromised, or a logon path this collection does not cover.

### `dedale_injected:L1` / `CASE-001`

*Provenance:* real benign DEDALE background + injected attack rows (labelled). *Answer key:* reports/m19b/cases/dedale_injected/L1/labels.json, via ath.evaluation.external_labels.

Real benign DEDALE background with a labelled endpoint x identity chain injected by scripts/m19b_inject_dedale.py -- not real data about an intrusion, however real the background is.

|  |  |
| --- | --- |
| leading rule | `ATH-005` |
| rules | `ATH-005` Failed logon burst followed by successful authentication, `ATH-007` Remote service execution (PsExec-style) |
| findings | `ATH-005:wlb-logon-0000069`, `ATH-007:wlb-process-0000428` |
| evidence ids | 14 -- `wlb-logon-0000069`, `wlb-logon-0000070`, `wlb-logon-0000071`, `wlb-logon-0000072`, `wlb-logon-0000073`, `wlb-logon-0000074`, `wlb-logon-0000075`, `wlb-logon-0000076`, `wlb-logon-0000077`, `wlb-logon-0000078`, `wlb-logon-0000079`, `wlb-logon-0000080`, `wlb-logon-0000081`, `wlb-process-0000428` |
| telemetry hash | `9d2e871227c9b92b17ca152f66fed92d870874e964caff0c840355015e8db088` |
| selection | the single case reports/m19b/cases/dedale_injected/L1/ forms when its winlogbeat/ directory is hunted, triaged and correlated |

**Necessity audit.** Domains with materially relevant evidence: endpoint, identity. Eligible at step 0: endpoint, identity (2 domain specialist(s)). Eligible over the whole deterministic run: attack, endpoint, identity. Independent evidence sources: 2 (1 endpoint, 13 identity). Qualifies: **YES**.

*Condition 3 (what synthesis could change):* Only the combination de-escalates, and the next action it produces -- close it, and ask why an old password was still cached at CLIENT7 -- is not reachable from either domain alone.

*Measured synthesis statement:* Synthesis across endpoint (what executed on the host and what started it), identity (whose credentials were used and from where) can change the verdict: each domain's finding is explicable on its own, and the other domain's rows are what decide whether that explanation survives. The case carries 1 endpoint row(s), 13 identity row(s), spanning the Execution, Persistence, Credential Access, Lateral Movement tactic(s); a verdict reached from one domain alone cannot exclude the benign reading the other domain's rows rule out.

**Pre-registered CDER links.**

| link | stage transition | identity event | endpoint event | note |
| --- | --- | --- | --- | --- |
| `L1-LINK-1` | 2-logon-after-unlock -> 3-remote-support-action | `wlb-logon-0000081` (`host=CLIENT9.breach.local;channel=Security;record_id=22458`) | `wlb-process-0000428` (`host=CLIENT9.breach.local;channel=Microsoft-Windows-Sysmon/Operational;record_id=815633`) | the authentication that the service-launched shell on the same host followed; the only cross-domain join this architecture can make (auth_then_exec) |
| `L1-LINK-2` | 2-logon-after-unlock -> 4-support-commands | `wlb-logon-0000081` (`host=CLIENT9.breach.local;channel=Security;record_id=22458`) | `wlb-process-0000429` (`host=CLIENT9.breach.local;channel=Microsoft-Windows-Sysmon/Operational;record_id=815634`) | the same authentication and the first command run under the shell it explains. Deliberately harder than LINK-1: no finding cites this process row, so recovering |

**Rubric.** Stages (reports/m19b/cases/dedale_injected/L1/labels.json, scenario `administrator-lockout-then-remote-support`): `1-stale-credential-lockout`, `2-logon-after-unlock`, `3-remote-support-action`, `4-support-commands`. Verdict: **benign**. Next action, written before any run: Close it as a service-desk action and ask why CLIENT7 still held client9's old password, because a lockout cascade, an account that owns the target host and a spooler restart are a ticket rather than an intrusion.

### `dedale_injected:L2` / `CASE-001`

*Provenance:* real benign DEDALE background + injected attack rows (labelled). *Answer key:* reports/m19b/cases/dedale_injected/L2/labels.json, via ath.evaluation.external_labels.

Real benign DEDALE background with a labelled endpoint x identity chain injected by scripts/m19b_inject_dedale.py -- not real data about an intrusion, however real the background is.

|  |  |
| --- | --- |
| leading rule | `ATH-005` |
| rules | `ATH-005` Failed logon burst followed by successful authentication, `ATH-007` Remote service execution (PsExec-style) |
| findings | `ATH-005:wlb-logon-0000002`, `ATH-007:wlb-process-0000066` |
| evidence ids | 14 -- `wlb-logon-0000002`, `wlb-logon-0000003`, `wlb-logon-0000004`, `wlb-logon-0000005`, `wlb-logon-0000006`, `wlb-logon-0000007`, `wlb-logon-0000008`, `wlb-logon-0000009`, `wlb-logon-0000011`, `wlb-logon-0000012`, `wlb-logon-0000013`, `wlb-logon-0000015`, `wlb-logon-0000016`, `wlb-process-0000066` |
| telemetry hash | `d68f234d5284b8ac2d0215a864076e54d74c9a4d9ad25f7def6173397e53a750` |
| selection | the single case reports/m19b/cases/dedale_injected/L2/ forms when its winlogbeat/ directory is hunted, triaged and correlated |

**Necessity audit.** Domains with materially relevant evidence: endpoint, identity. Eligible at step 0: endpoint, identity (2 domain specialist(s)). Eligible over the whole deterministic run: attack, endpoint, identity. Independent evidence sources: 2 (1 endpoint, 13 identity). Qualifies: **YES**.

*Condition 3 (what synthesis could change):* Endpoint alone is a MEDIUM finding an analyst sets aside without ever learning that a dozen failed logons preceded it, and so without asking the one question that matters -- **is anything else on this estate still authenticating with the old password?**

*Measured synthesis statement:* Synthesis across endpoint (what executed on the host and what started it), identity (whose credentials were used and from where) can change the verdict: each domain's finding is explicable on its own, and the other domain's rows are what decide whether that explanation survives. The case carries 1 endpoint row(s), 13 identity row(s), spanning the Execution, Persistence, Credential Access tactic(s); a verdict reached from one domain alone cannot exclude the benign reading the other domain's rows rule out.

**Pre-registered CDER links.**

| link | stage transition | identity event | endpoint event | note |
| --- | --- | --- | --- | --- |
| `L2-LINK-1` | 2-credential-corrected -> 3-service-started-script | `wlb-logon-0000016` (`host=CLIENT12.breach.local;channel=Security;record_id=30270`) | `wlb-process-0000066` (`host=CLIENT12.breach.local;channel=Microsoft-Windows-Sysmon/Operational;record_id=4438849`) | the authentication that the service-launched shell on the same host followed; the only cross-domain join this architecture can make (auth_then_exec) |

**Rubric.** Stages (reports/m19b/cases/dedale_injected/L2/labels.json, scenario `scheduled-backup-with-stale-password`): `1-stale-scheduled-credential`, `2-credential-corrected`, `3-service-started-script`. Verdict: **benign**. Next action, written before any run: Close it as an operational finding, fix the stored credential on the nightly backup job, and check whether anything else on the estate is still authenticating with the old password.

### `flaws_cloud` / `CASE-182`

*Provenance:* real unlabelled. *Answer key:* none (unlabelled corpus).

Principals named by this case's rows: backup. Pinned as CASE-182 at freeze time; the case number is recorded, never relied on.

|  |  |
| --- | --- |
| leading rule | `AWS-004` |
| rules | `ATH-005` Failed logon burst followed by successful authentication, `AWS-004` Authorization-denial burst |
| findings | `ATH-005:cloudtrail-logon-068736`, `AWS-004:cloudtrail-control-1738515` |
| evidence ids | 66 -- `cloudtrail-control-1738515`, `cloudtrail-control-1738516`, `cloudtrail-control-1738517`, `cloudtrail-control-1738518`, `cloudtrail-control-1738520`, `cloudtrail-control-1738609`, `cloudtrail-control-1738613`, `cloudtrail-control-1738614`, `cloudtrail-control-1738615`, `cloudtrail-control-1738616`, `cloudtrail-control-1738619`, `cloudtrail-control-1738621`, `cloudtrail-control-1738623`, `cloudtrail-control-1738626`, `cloudtrail-control-1738631`, `cloudtrail-control-1738633`, `cloudtrail-control-1738637`, `cloudtrail-control-1738640`, `cloudtrail-control-1738641`, `cloudtrail-control-1738643`, `cloudtrail-logon-068736`, `cloudtrail-logon-068737`, `cloudtrail-logon-068738`, `cloudtrail-logon-068739`, `cloudtrail-logon-068740`, `cloudtrail-logon-068741`, `cloudtrail-logon-068742`, `cloudtrail-logon-068743`, `cloudtrail-logon-068744`, `cloudtrail-logon-068745`, `cloudtrail-logon-068746`, `cloudtrail-logon-068747`, `cloudtrail-logon-068748`, `cloudtrail-logon-068749`, `cloudtrail-logon-068750`, `cloudtrail-logon-068751`, `cloudtrail-logon-068752`, `cloudtrail-logon-068753`, `cloudtrail-logon-068754`, `cloudtrail-logon-068755`, `cloudtrail-logon-068756`, `cloudtrail-logon-068757`, `cloudtrail-logon-068758`, `cloudtrail-logon-068759`, `cloudtrail-logon-068760`, `cloudtrail-logon-068761`, `cloudtrail-logon-068762`, `cloudtrail-logon-068763`, `cloudtrail-logon-068764`, `cloudtrail-logon-068765`, `cloudtrail-logon-068766`, `cloudtrail-logon-068767`, `cloudtrail-logon-068768`, `cloudtrail-logon-068769`, `cloudtrail-logon-068770`, `cloudtrail-logon-068771`, `cloudtrail-logon-068772`, `cloudtrail-logon-068773`, `cloudtrail-logon-068774`, `cloudtrail-logon-068775`, `cloudtrail-logon-068776`, `cloudtrail-logon-068777`, `cloudtrail-logon-068778`, `cloudtrail-logon-068779`, `cloudtrail-logon-068780`, `cloudtrail-logon-068781` |
| telemetry hash | `d124dc925e7743723f164b2bb800d3012f1a678fd0864d2521e4450a4ce4f0c4` |
| selection | the first identity x control_plane case the M19b link forms on real CloudTrail: a failed-logon burst and an authorization-denial burst by the principal `backup`, spanning 1009s from 2020-04-11T12:40:01Z; pinned by member finding ids and the principal 'backup', not by case number |

**Necessity audit.** Domains with materially relevant evidence: control_plane, identity. Eligible at step 0: identity, control_plane (2 domain specialist(s)). Eligible over the whole deterministic run: attack, control_plane, identity. Independent evidence sources: 2 (20 control_plane, 46 identity). Qualifies: **YES**.

*Condition 3 (what synthesis could change):* Apart, each finding has a dull reading and gets a routine answer: a burst of failed logons for `backup` that never succeeds is someone mistyping a password, and an authorization-denial burst by `backup` minutes later is a script with a stale policy. Together -- one principal failing to authenticate and then being refused across the control plane inside one 1009-second window -- they read as a caller probing what a credential can reach, which makes the next question whose hands are on that credential rather than a password reset and a policy fix filed separately.

*Measured synthesis statement:* Synthesis across control_plane (which cloud/cluster resources an identity acted on), identity (whose credentials were used and from where) can change the verdict: each domain's finding is explicable on its own, and the other domain's rows are what decide whether that explanation survives. The case carries 20 control_plane row(s), 46 identity row(s), spanning the Credential Access, Discovery tactic(s); a verdict reached from one domain alone cannot exclude the benign reading the other domain's rows rule out.

**Pre-registered CDER links:** none. CDER on this case is `UNAVAILABLE (unlabelled)`.

**Rubric.** Stages (the member findings' distinct rule titles -- this corpus has no ground truth, so it has no stages, and saying so is the measurement): `Failed logon burst followed by successful authentication`, `Authorization-denial burst`. Verdict: **unknown**. Next action, written before any run: If the two findings are one actor, rotate the `backup` principal's credentials and review every management call it made in the window; if they are not, the denials are a policy bug and the logins are a person, and the case should be split rather than escalated.

### `flaws_cloud` / `CASE-256`

*Provenance:* real unlabelled. *Answer key:* none (unlabelled corpus).

Principals named by this case's rows: Level6. Pinned as CASE-256 at freeze time; the case number is recorded, never relied on.

|  |  |
| --- | --- |
| leading rule | `AWS-004` |
| rules | `ATH-005` Failed logon burst followed by successful authentication, `AWS-003` Cloud service discovery burst, `AWS-004` Authorization-denial burst |
| findings | `ATH-005:cloudtrail-logon-078417`, `AWS-003:cloudtrail-control-1817072`, `AWS-003:cloudtrail-control-1817745`, `AWS-003:cloudtrail-control-1818026`, `AWS-004:cloudtrail-control-1817217`, `AWS-004:cloudtrail-control-1817767`, `AWS-004:cloudtrail-control-1818026` |
| evidence ids | 105 -- `cloudtrail-control-1817072`, `cloudtrail-control-1817082`, `cloudtrail-control-1817085`, `cloudtrail-control-1817088`, `cloudtrail-control-1817159`, `cloudtrail-control-1817175`, `cloudtrail-control-1817217`, `cloudtrail-control-1817246`, `cloudtrail-control-1817317`, `cloudtrail-control-1817318`, `cloudtrail-control-1817321`, `cloudtrail-control-1817322`, `cloudtrail-control-1817323`, `cloudtrail-control-1817324`, `cloudtrail-control-1817351`, `cloudtrail-control-1817352`, `cloudtrail-control-1817356`, `cloudtrail-control-1817358`, `cloudtrail-control-1817359`, `cloudtrail-control-1817361`, `cloudtrail-control-1817365`, `cloudtrail-control-1817368`, `cloudtrail-control-1817369`, `cloudtrail-control-1817371`, `cloudtrail-control-1817372`, `cloudtrail-control-1817373`, `cloudtrail-control-1817374`, `cloudtrail-control-1817375`, `cloudtrail-control-1817376`, `cloudtrail-control-1817377`, `cloudtrail-control-1817378`, `cloudtrail-control-1817466`, `cloudtrail-control-1817745`, `cloudtrail-control-1817767`, `cloudtrail-control-1817774`, `cloudtrail-control-1817775`, `cloudtrail-control-1817791`, `cloudtrail-control-1817809`, `cloudtrail-control-1817861`, `cloudtrail-control-1817863`, `cloudtrail-control-1817865`, `cloudtrail-control-1817866`, `cloudtrail-control-1817867`, `cloudtrail-control-1817868`, `cloudtrail-control-1817875`, `cloudtrail-control-1817891`, `cloudtrail-control-1817893`, `cloudtrail-control-1817897`, `cloudtrail-control-1817901`, `cloudtrail-control-1817902`, `cloudtrail-control-1817907`, `cloudtrail-control-1817908`, `cloudtrail-control-1817909`, `cloudtrail-control-1817914`, `cloudtrail-control-1817917`, `cloudtrail-control-1817918`, `cloudtrail-control-1817919`, `cloudtrail-control-1817920`, `cloudtrail-control-1817921`, `cloudtrail-control-1817922`, `cloudtrail-control-1817923`, `cloudtrail-control-1817928`, `cloudtrail-control-1818004`, `cloudtrail-control-1818011`, `cloudtrail-control-1818026`, `cloudtrail-control-1818027`, `cloudtrail-control-1818028`, `cloudtrail-control-1818029`, `cloudtrail-control-1818030`, `cloudtrail-control-1818031`, `cloudtrail-control-1818032`, `cloudtrail-control-1818033`, `cloudtrail-control-1818034`, `cloudtrail-control-1818035`, `cloudtrail-control-1818036`, `cloudtrail-control-1818044`, `cloudtrail-control-1818229`, `cloudtrail-control-1818231`, `cloudtrail-control-1818233`, `cloudtrail-control-1818234`, `cloudtrail-control-1818236`, `cloudtrail-control-1818237`, `cloudtrail-control-1818238`, `cloudtrail-control-1818239`, `cloudtrail-control-1818240`, `cloudtrail-control-1818241`, `cloudtrail-control-1818242`, `cloudtrail-control-1818243`, `cloudtrail-control-1818244`, `cloudtrail-control-1818245`, `cloudtrail-control-1818246`, `cloudtrail-control-1818251`, `cloudtrail-control-1818306`, `cloudtrail-control-1818319`, `cloudtrail-logon-078417`, `cloudtrail-logon-078418`, `cloudtrail-logon-078419`, `cloudtrail-logon-078420`, `cloudtrail-logon-078421`, `cloudtrail-logon-078422`, `cloudtrail-logon-078423`, `cloudtrail-logon-078424`, `cloudtrail-logon-078425`, `cloudtrail-logon-078426`, `cloudtrail-logon-078427` |
| telemetry hash | `d124dc925e7743723f164b2bb800d3012f1a678fd0864d2521e4450a4ce4f0c4` |
| selection | the second: seven findings naming the principal `Level6` -- a failed-logon burst, three service-discovery bursts and three denial bursts -- spanning 2017s from 2020-09-21T03:54:58Z; pinned by member finding ids and the principal 'Level6', not by case number |

**Necessity audit.** Domains with materially relevant evidence: control_plane, identity. Eligible at step 0: identity, control_plane (2 domain specialist(s)). Eligible over the whole deterministic run: attack, control_plane, identity. Independent evidence sources: 2 (94 control_plane, 11 identity). Qualifies: **YES**.

*Condition 3 (what synthesis could change):* Apart, the identity burst is a login problem and the six control-plane findings are a permissions problem, and on a deliberately vulnerable public account both are closed unread. Together they say the principal whose authentication is failing is the same principal enumerating services and collecting refusals across the same 2017-second window, so the question stops being "why was this call denied" and becomes "whose hands are on this credential" -- which changes the priority and who is asked, on evidence the corpus always carried and the correlator could not read until M19b.

*Measured synthesis statement:* Synthesis across control_plane (which cloud/cluster resources an identity acted on), identity (whose credentials were used and from where) can change the verdict: each domain's finding is explicable on its own, and the other domain's rows are what decide whether that explanation survives. The case carries 94 control_plane row(s), 11 identity row(s), spanning the Credential Access, Discovery tactic(s); a verdict reached from one domain alone cannot exclude the benign reading the other domain's rows rule out.

**Pre-registered CDER links:** none. CDER on this case is `UNAVAILABLE (unlabelled)`.

**Rubric.** Stages (the member findings' distinct rule titles -- this corpus has no ground truth, so it has no stages, and saying so is the measurement): `Failed logon burst followed by successful authentication`, `Cloud service discovery burst`, `Authorization-denial burst`. Verdict: **unknown**. Next action, written before any run: If the two findings are one actor, rotate `Level6`'s credentials and review what it reached on the control plane during the 34 minutes the case spans, starting with the calls that were allowed rather than the ones that were refused.

## Input hashes

Injected case directories (every file, sha256 over `path:digest` lines):

| case | directory | sha256 | files |
| --- | --- | --- | --- |
| M1 | `reports/m19b/cases/dedale_injected/M1` | `477fd069b908fa969cbb79e2c32d6807c35b523bb1fcfebc1ff9eb2e4653202d` | 4 |
| M2 | `reports/m19b/cases/dedale_injected/M2` | `eccbced1794415c39a61854261a0306ada4602067655f56e1d8c9caeb30373e1` | 4 |
| M3 | `reports/m19b/cases/dedale_injected/M3` | `1bd0f2b0083efb532d7e3c4003c36c0f188aca15525ec18dd037d72b058cd3a0` | 4 |
| M4 | `reports/m19b/cases/dedale_injected/M4` | `e5bcc1ffa79046be6daea4336969362fc883accf71c819e48a4ba2060820064f` | 4 |
| L1 | `reports/m19b/cases/dedale_injected/L1` | `ea797b1cceb175909205c29174d0db6af2e4e124ddf4b529ff95151586e8583c` | 4 |
| L2 | `reports/m19b/cases/dedale_injected/L2` | `fcb74cb4ab28a33b4bd59d19110f4dc7bb74443e574986e6fa3917f4af51957f` | 4 |

DEDALE source days, as `reports/m19b/cases/dedale_injected/MANIFEST.json` records them:

| file | sha256 | bytes |
| --- | --- | --- |
| D03/D03_2024-12-25.jsonl | `97c80aeb5554656a2ad7a417df0a33e39df9e9f7621a58599411576fe74cde7b` | 314452660 |
| D18/D18_2025-01-09.jsonl | `2c7e8f3b63f28d14fc8a30e44672efdc2ac09ea695f00dc61476d5f4c0a16299` | 257009422 |

flaws.cloud, from `data/external/MANIFEST.json` (fetched 2026-09-10):

| file | sha256 | bytes |
| --- | --- | --- |
| flaws_cloud/raw/flaws_cloudtrail_logs.tar | `f26c2b8da56bb00d695a57f00f86208117582b9216bb52424d68e718ca2a96aa` | 251688960 |

Generator `scripts/m19b_inject_dedale.py` sha256 `d5f97a3db2132f892808f6f4c44f9d913b7e91b946c7a1d5d26f64d6191bea91` (seed 19026); `data/raw/ground_truth.json` sha256 `892ff4b625e7278bbbaebaf2721b975863a5345426f720595d10d2c2cb04c75b`.

## How the links were defined

* **dedale_injected:***: the `links` block each case's `labels.json` pre-registers, written by scripts/m19b_inject_dedale.py at generation time; native `host;channel;record_id` refs resolved to ATH event ids by ath.evaluation.external_labels.resolve_refs, and refused if any ref names no ingested row
* **synthetic:INC-001**: every (source, target) pair of ground-truth event ids where the source is in stage 6-credential-access or 7-brute-force and the target is in the stage that follows them, 8-lateral-movement, kept only when the two ids belong to different domains. Stage 6's single id is a process row and stage 8's is a process row, so every surviving pair is identity x endpoint: one of the fifteen failed/successful network logons paired with the service-launched shell they explain.
* **flaws_cloud**: none. The corpus has no labels, so no link can be pre-registered and the CDER column reads UNAVAILABLE (unlabelled)

## Limitations

* **Six of the nine cases are constructed.** `dedale_injected:*` is real benign DEDALE telemetry with a hand-written chain injected into it. The background is real; the intrusion is not, and no row of this benchmark should be read as evidence about real attacker behaviour.
* **Every constructed case is endpoint x identity**, because that is the only cross-domain pair `ath.correlation.correlator` can form on Winlogbeat telemetry. The benchmark therefore measures whether a crew helps on *one* kind of cross-domain investigation (VERIFIED FROM CODE; the argument is in each CASE.md and in `reports/m19b/necessity/AUDIT.md`).
* **The two real cases carry no ground truth.** flaws.cloud names no event ids in any published narrative, so their verdict is `unknown`, their CDER is `UNAVAILABLE (unlabelled)`, and nothing here claims they are intrusions. They are in the set because they are the only *real* cases in this repository on which two domain specialists have materially relevant evidence.
* **INC-001's links are mechanical.** The plan defines a link as a pair of evidence ids two domains contribute to one stage transition; ground truth gives stage membership and not a representative row, so every (source, target) pair of ground-truth event ids where the source is in stage 6-credential-access or 7-brute-force and the target is in the stage that follows them, 8-lateral-movement, kept only when the two ids belong to different domains -- which makes the denominator fifteen near-identical links rather than one. A CDER of 1/15 on this case means the same thing as 1/1 would; the ratio is comparable between arms and not between cases.
* **A rubric's next action is one analyst's judgement**, written before any run and committed so it cannot be revised afterwards. It is a pre-registration, not a ground truth, and a later task may not promote it to one.
* **The held-out case `HELDOUT_H1` is not here**, and its answer key is sealed. Nothing in this manifest, this script, or its tests opens it.
