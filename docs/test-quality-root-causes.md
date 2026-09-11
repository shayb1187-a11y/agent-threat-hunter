# Why 704 green tests missed what one day of real data found

Date: 2026-09-12. Input: the M14 measurements in [m14-validation-report.md](m14-validation-report.md).
Scope: root causes in the *tests* (not the rules), and a plan to fix the tests so the same
class of defect turns the suite red before real data has to.

## The defects the suite passed over

| Defect found on real data | Test that should have caught it | Why it did not |
|---|---|---|
| ATH-004 fires on `lsass.exe` itself (30/day) | `test_ath004_silent_on_clean_telemetry` | "clean" = the synthetic data minus the one `comsvcs` line; that data never contains `lsass.exe` starting, so silence was vacuous |
| Kubernetes exec logged as verb `get` / status 101 | `test_pod_exec_by_the_newly_privileged_account_is_mapped` | fixture authored with `verb: create`, `code: 200`; no record was ever captured from an apiserver |
| RBAC subject `ci-runner` vs audit user `system:serviceaccount:ci:ci-runner` | `test_escalation_grant_targets_a_different_service_account` | fixture wrote the audit-username form *into* the subject, which no cluster does; the rule test built canonical rows by hand (`_grant_row`, `_exec_row`), so adapter and rule never met on a real-shaped record |
| Triage inert on 124 of 124 real findings | `test_triage.py` | 10 of 11 triage findings under test are LOW/MEDIUM; the `graded_high_by_detection` veto has one existence assertion and no rate measurement, while every cloud/K8s rule and ATH-004 emit HIGH+ |
| K8S-001 on every legitimate `cluster-admin` binding (2,070/day) | none | no benign Kubernetes corpus exists in tests; the fixture has one benign binding (`view`) |
| Service-invoked `AssumeRole` dropped (57,912 records) | `test_malformed_records_are_dropped_not_raised` | the fixture's "no usable principal" record was invented to be unattributable; a real `AWSService` identity was never in the fixture |
| ATH-005 HIGH with no success (35/36) | `test_ath005_high_not_critical_without_a_success` | the test pins the current behaviour as correct; nothing measures how often the no-success branch fires on benign data |

## Root causes

**RC1. One synthetic world, and the tests are its mirror.** 27 test files build their data
from `ath.telemetry.generator`. Its benign background is 13 process templates and a
four-hour window on 8 hosts. A real DEDALE day has 99 distinct process names, 43,994
creates and 13,667 service logons on 30 hosts, with a boot chain (`wininit.exe ->
lsass.exe`, `services.exe -> svchost.exe` x N, `CompatTelRunner.exe -> powershell.exe`) on
every host every morning. The templates were written by the rule authors with the rules in
mind (the comment says so: "this is why powershell ran is NOT a detection"), so they cover
the false positives the authors already knew, and nothing else. A rule that matches the
image path of the process it monitors cannot be caught by a corpus in which that process
never starts.

**RC2. Fixtures authored from documentation or memory, not captured.** The Defender
fixture verified *column names* against Microsoft Learn and invented every value
(`SHA1 = deadbeef`). The Kubernetes and CloudTrail fixtures were typed from the API shape
as remembered. The docstrings say "verified" and the tests inherit that confidence. Every
adapter defect M14 found was a *value* convention (verb, status code, subject spelling,
identity union type), none was a column name.

**RC3. Negative controls are "attack minus one", not "benign plus look-alike".** 13 silence
assertions across 49 hunting tests, almost all of the form "remove the labelled event,
assert `[]`". Only three rules (ATH-002, ATH-006, ATH-011) have a benign look-alike in the
generator. Each rule declares a `false_positives` list in prose, and no test exercises any
of those sentences: the declared false positives are documentation, not a contract.

**RC4. Rule tests bypass the adapters.** `tests/test_control_plane_rules.py` constructs
canonical rows directly (`verb="exec"`, `target_actor="ci-runner"`). That tests the rule
against the vocabulary the test author assumed the adapter emits. Before M14 only two
files ran `run_hunt` on adapter output (Defender integration, CloudTrail); the
adapter-to-rule vocabulary agreement was otherwise untested, which is exactly where three
of the seven defects lived.

**RC5. Severity coverage in triage tests does not match what rules emit.** The benign
layer defers at HIGH by design. The tests exercise it at LOW and MEDIUM, where it can act,
and assert the HIGH veto exists. Nothing asks "on a benign corpus, what fraction of
findings does the veto swallow" -- which on every real source was 100%.

**RC6. Measured-number tests ratchet in one direction.** `test_incidents.py` pins
`noise_cases == 1`, `case_precision == 0.5`, `quiet.findings == 2`. That is right for
regression, but it also enshrines known defects as expected values with no marker saying
"this number is a defect". A fix that improves them makes the suite red for the wrong
reason, and a defect that stays never makes it red at all.

**RC7. Constants with an external truth are tested against themselves.**
`LOGON_TYPE_STRING_TO_CODE` was checked against Microsoft's five documented strings, which
is the right pattern. `_EXEC_VERBS`, `MANAGEMENT_EVENTS`, `OFFICE_APPLICATIONS` (no
LibreOffice) and `AUTH_EVENTS` had no external-truth check; a test that a tuple equals a
hand-typed tuple proves nothing.

**Minor, `tests/test_language.py`** (the file open in the editor): the tests themselves
are sound. The module-scoped fixture generates and writes the entire synthetic dataset to
obtain one real `event_id`; a two-row frame would do. Not a correctness problem.

## Plan

Ordered by how much of the table above each step would have turned red.

**P1. A real-shaped fixture corpus, small and license-clean.** Commit hand-cut samples
under `tests/fixtures/real_shaped/` with a provenance header (source, record ids,
license) on each:

- DEDALE (CC BY 4.0): one host's Sysmon 1 and Security 4624/4625 for a boot hour plus a
  working hour, including `wininit.exe -> lsass.exe`, `services.exe -> svchost.exe`,
  `CompatTelRunner.exe -> powershell.exe`, LibreOffice opening documents. Under 100 KB.
- Kubernetes CI (public bucket, cited): 200 lines with bootstrap `cluster-admin`
  bindings, `e2e-test-privileged-psp` bindings, `get`-verb execs with 101,
  `serviceaccounts/token`, Metadata-level and RequestResponse-level events.
- CloudTrail: flaws.cloud cannot be committed (license unverified), so the fixture stays
  synthetic but is *shaped from the real histogram*: `AWSService` identities with
  `invokedBy`, `AssumedRole` ARNs, `AccessDenied` and `RequestLimitExceeded` errors,
  gzipped members in a tar.

**P2. Every rule gets a benign-corpus test and a look-alike contract.** For each rule:
`test_<rule>_silent_on_real_shaped_benign_corpus`, and one test per sentence in the rule's
declared `false_positives`. A meta-test enforces the contract: every declared false
positive must name a test id (add `false_positive_tests: tuple[str, ...]` beside the prose,
or parse the prose keys), so a rule cannot document a false positive it does not test.
Start with the three measured: ATH-004 boot `lsass.exe`, K8S-001 bootstrap grants,
ATH-005 no-success burst.

**P3. Adapter-to-rule contract tests.** For each adapter, run `run_hunt` on the adapter's
output from the P1 fixture: a spliced positive must fire the intended rule and the benign
remainder must not. Retire hand-built canonical rows in rule tests where an adapter path
exists, or keep them only alongside an adapter-produced twin.

**P4. Severity-aware triage tests.** A meta-test collects every severity a registered
detector can emit and requires at least one triage test at each. Add
`test_triage_has_purchase_on_a_benign_corpus`: on the P1 benign corpus, triage load
reduction must exceed zero. It fails today; mark it `xfail(strict=True, reason="M15-4:
HIGH veto makes triage inert")` so it flips the suite when the design decision lands
rather than being edited to pass.

**P5. Regression artifacts become tests.** The before/after rows in `reports/m14/`
already are the evidence: `test_k8s_ci_shaped_execs_are_ingested` (was 0 of 5,962),
`test_dedale_shaped_boot_lsass_is_not_credential_access` (xfail strict until ATH-004 is
fixed), `test_service_invoked_assume_role_is_attributed` (already added). Every future
real-data defect gets the same treatment before it is fixed.

**P6. Replace vacuous silence tests.** Each "strip the labelled event and assert `[]`"
test is rewritten against the P1 corpus that contains the rule's own target process and
its look-alikes. The stripped variant may stay as a second assertion; it may no longer be
the only one.

**P7. Give the measured-number tests a direction.** Keep the pinned values, and beside
each one that encodes a known defect add a strict `xfail` target test naming the M15 item.
A fix then produces an unexpected pass (suite red, deliberately), and the pinned number
is updated in the same change.

**P8. External-truth checks for vocabularies.** `OFFICE_APPLICATIONS`, `_EXEC_VERBS`,
`AUTH_EVENTS`, `MANAGEMENT_EVENTS`: each gets a test against a captured sample or a fetched
document, not against a retyped list. Where no external truth is available, the test says
so in its docstring instead of pretending.

**P9. Generator, last.** Adding boot chains and more processes to the generator makes it
less wrong but keeps the mirror problem (RC1). Use it for volume and labels; use P1 for
shape. Do not spend effort here before P1-P6.

## Acceptance

After P1-P6 and before any rule is changed, the suite must be red in exactly the places
the M14 report flagged and green everywhere else:

| Expected red (strict xfail) | Flagged by |
|---|---|
| ATH-004 on boot `lsass.exe` | DEDALE D03/D15 |
| K8S-001 on bootstrap `cluster-admin` bindings | Kubernetes CI |
| ATH-005 severity independent of success | flaws.cloud |
| triage reduction 0% on a benign corpus | all real sources |
| LibreOffice not an Office application | DEDALE D15 |

Anything the M14 report flagged that the rebuilt suite still passes is a test the plan
missed, and goes back into this document. Every fix in M15 then flips one strict xfail,
and the pinned number changes in the same commit.

## Executed (2026-09-12)

P1-P8 are in place; P9 (generator diversification) deliberately not started. 778 tests
pass, 11 strict xfails state the targets. No rule, threshold or benign signal changed.

| Step | What landed | Where |
|---|---|---|
| P1 | Real-shaped corpus: 25 DEDALE records (CLIENT2 boot chain, service logons, CompatTelRunner/PowerShell, LibreOffice), 12 Kubernetes CI records (bootstrap `cluster-admin`, per-test SA grants, `get`-verb 101 execs, SA token, secret read), 68 shaped CloudTrail records in a tar of gz members; provenance file beside each | `tests/fixtures/real_shaped/`, `scripts/cut_real_shaped_fixtures.py` |
| P2 | 49 declared false positives, 49 cases; meta-test fails on a declared sentence with no case, a case for an undeclared sentence, or sentence drift. 5 of 49 pins differed from my first guess and were corrected to the measured behaviour, each with a note (wildcard source decides ATH-008; AWS-001 keys on the grantee acting, so its second declared false positive cannot even trip it) | `tests/test_false_positive_contracts.py`, `tests/_builders.py` |
| P3 | Adapter-to-rule contracts on the corpus: spliced positives fire through the real path (comsvcs MiniDump, Office spawn, grantee exec); pinned false positives; vocabulary checks against captured verbs | `tests/test_real_shaped_corpus.py` |
| P4 | Severity contract: the emitted set is pinned (MEDIUM/HIGH/CRITICAL), the veto boundary is pinned per severity with the same benign evidence, and the 11 rules that are untriageable today are named | `tests/test_triage_severity_coverage.py` |
| P5 | Regression artifacts as tests: execs ingested (was 0/5,962), service-invoked calls attributed (was 57,912 dropped), representation gaps counted | `tests/test_real_shaped_corpus.py` |
| P6 | The vacuous ATH-004 silence test says so in its docstring and points at the corpus test | `tests/test_hunting.py` |
| P7 | Strict-xfail targets beside the pinned incident numbers | `tests/test_incidents.py` |
| P8 | `_EXEC_VERBS` against captured exec verbs; `AUTH_EVENTS` against the shaped corpus; `OFFICE_APPLICATIONS` must include LibreOffice (target) | `tests/test_real_shaped_corpus.py` |

### Acceptance: red in exactly the flagged places

| Flagged by M14 | Strict xfail(s) |
|---|---|
| ATH-004 on boot `lsass.exe` | `test_target_dedale_benign_boot_hour_is_silent` |
| K8S-001 on bootstrap `cluster-admin` bindings | `test_target_k8s_benign_bootstrap_is_silent`, FP contract `K8S-001[0]` |
| ATH-005 severity independent of success | FP contracts `ATH-005[0]`, `ATH-005[3]`, `test_target_cloudtrail_no_success_burst_is_not_high` |
| Triage 0% on a benign corpus | `test_target_triage_has_purchase_on_a_benign_corpus` |
| LibreOffice not an Office application | `test_target_libreoffice_spawning_an_interpreter_is_an_office_spawn`, `test_target_office_application_vocabulary_includes_libreoffice` |
| Known benign look-alike case (README) | `test_target_windows_incident_has_no_noise_case`, `test_target_quiet_day_raises_no_case` |

Each M15 fix must flip exactly one of these to an unexpected pass; the pinned expectation
is updated in the same commit. Nothing the M14 report flagged remains green-by-omission.
