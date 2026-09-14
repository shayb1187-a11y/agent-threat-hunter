"""M19b T8: freeze, run, score and grade the cross-specialist necessity benchmark.

What this is
------------
The harness the pre-registration (``reports/m19b/PREREGISTERED.md``) describes, and
nothing more. It runs the three M19 arms over the nine frozen M19b cases
(``reports/m19b/MANIFEST.json``), scores them with the M19 metrics plus the T6 necessity
metrics plus the three rules the pre-registration fixed as constants, and grades H1-H6
and the section-5 decision rule mechanically.

Four commands, in the order they may be used::

    python scripts/m19b_ablation.py substrings          # before any run; committed
    python scripts/m19b_ablation.py freeze
    python scripts/m19b_ablation.py run --arm A --repeat 2
    python scripts/m19b_ablation.py score --arm A
    python scripts/m19b_ablation.py grade

Why a fourth ablation script rather than an edit to ``scripts/m19_ablation.py``
-------------------------------------------------------------------------------
M19's script is part of a finished experiment; ``scripts/m19b_manifest.py`` froze this
milestone's benchmark and ran arm A to establish the deterministic baseline before the
metrics that grade it existed. Both stay as they are. What is *not* re-implemented here
is anything either of them already does: the arms, the run loop, the equal-footing
assertion, the request observer, the manifest reader, the corpus loaders, the M19
scoring definitions, the environment freeze and the ``reports/m19/`` write guard are all
imported. What is new is only what the pre-registration added:

* the **one permitted divergence** from M19 -- ``tool_output_budget = 4096`` for the two
  model arms -- recorded in the freeze and re-asserted against the live code before a
  model arm may run (:data:`FROZEN_TOOL_OUTPUT_BUDGET`);
* the **specificity rule** that separates a cross-domain claim from a blanket one
  (:data:`SPECIFIC_MAX_FRACTION`, :data:`SPECIFIC_MAX_IDS`);
* **stage recovery** and the **completeness** ratio H1 is graded on;
* the per-case **conclusion substrings**, derived from the manifest's rubric text before
  any run and committed as ``reports/m19b/RUBRIC_SUBSTRINGS.json``;
* the **grader**, which reads counts and cited-id sets and never a model's prose.

The grader reads no prose
--------------------------
Every hypothesis in section 4 is graded from integers and from sets of evidence ids. The
one place a *string* is read at all is the conclusion-substring mechanism, which is
``ath.evaluation.incidents``'s and which compares a fixed, pre-registered substring
against a claim's text -- a test asserts this file's implementation agrees with
``score_labels`` on a constructed state, so the two cannot drift. No summary, no ranking
and no judgement of quality is taken from what a model wrote.

``data/external/`` is gitignored and lives only in the primary checkout, so the commands
that load a corpus take ``--external`` and default to the sibling checkout's copy -- the
same default every other M19b script uses.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import time
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import m19_ablation as m19  # noqa: E402
import m19b_env as env19b  # noqa: E402
import m19b_link_report as link_report  # noqa: E402
import m19b_manifest as manifest_script  # noqa: E402
import m19b_necessity_audit as necessity_script  # noqa: E402

# The M19 write guard and the two guarded writers, imported rather than restated: the
# rule "M19b reports beside reports/m19/ and never into it" must have exactly one
# implementation, or a later edit to one copy silently exempts the other.
from m19b_robustness import _refuse_m19_path, write_artifact, write_text  # noqa: E402

from ath.agent.orchestrator import InvestigationConfig  # noqa: E402
from ath.evaluation.ablation import (  # noqa: E402
    ARM_A,
    ARM_B,
    ARM_C,
    ARM_BUILDERS,
    STEP_BUDGET,
    TOOL_CALL_CAP,
    ArmConfig,
    CaseManifest,
    CaseResult,
    CaseRubric,
    RubricItem,
    aggregate,
    context_size,
    cross_domain_claims,
    cross_domain_evidence_recovery,
    domain_of_telemetry,
    duplicate_tool_calls,
    identical,
    planner_activation,
    run_arm,
    scores_from_dict,
    state_payload,
    telemetry_hash,
    unique_cross_domain_contribution,
)
from ath.evaluation.ablation.environment import (  # noqa: E402
    ENVIRONMENT_JSON,
    ENVIRONMENT_MD,
    check_environment,
    live_values,
    sha256_text,
    tool_surface,
)
from ath.evaluation.ablation.scoring import RECOVERING_CLAIM_TYPES  # noqa: E402
from ath.evaluation.external_labels import (  # noqa: E402
    RESOLVED,
    load_external_labels,
    resolve_refs,
)
from ath.telemetry.loader import Telemetry, load_ground_truth  # noqa: E402

# --------------------------------------------------------------------------------------
# Where things live
# --------------------------------------------------------------------------------------

M19_DIR = ROOT / "reports" / "m19" / "ablation"
"""The frozen M19 experiment. Read-only for the whole of M19b; see ``_refuse_m19_path``."""

OUT_DIR = ROOT / "reports" / "m19b"
ABLATION_DIR = OUT_DIR / "ablation"
RUBRIC_SUBSTRINGS_PATH = OUT_DIR / "RUBRIC_SUBSTRINGS.json"
ORACLE_PATH = ABLATION_DIR / "ORACLE.json"
GRADING_JSON = ABLATION_DIR / "GRADING.json"
GRADING_MD = ABLATION_DIR / "GRADING.md"

DEFAULT_EXTERNAL = manifest_script.DEFAULT_EXTERNAL

PROTECTED_PATHS: tuple[Path, ...] = (ABLATION_DIR / "arm_A.json",)
"""Committed M19b artifacts this script may read but never rewrite.

``arm_A.json`` is T5c's deterministic baseline, produced and committed before the
metrics that grade it existed. A later arm A run is a *reproduction* of it -- which is
only a claim if the thing being reproduced is still the thing that was published. So
this script writes its own rows beside it (``arm_A_rep1.json``) and refuses, by path, to
write over it.
"""


def rel(path: Path) -> str:
    """A repository-relative path for a record, or the absolute one when it is outside.

    Artifacts name their inputs, and a test driving this harness over a temporary
    directory must not make that naming raise.
    """
    try:
        return str(Path(path).resolve().relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def refuse_protected(path: Path) -> Path:
    """Refuse a write to a committed M19b artifact. See :data:`PROTECTED_PATHS`."""
    resolved = Path(path).resolve()
    for protected in PROTECTED_PATHS:
        if resolved == protected.resolve():
            raise SystemExit(
                f"refusing to write {path}: it is a committed M19b artifact "
                "(T5c's arm A baseline). This run writes beside it and asserts "
                "reproduction against it; overwriting it would delete the thing the "
                "assertion is about."
            )
    return Path(path)


def guarded(path: Path) -> Path:
    """Both write guards, in one call: never under ``reports/m19/``, never over T5c's."""
    return refuse_protected(_refuse_m19_path(path))


# --------------------------------------------------------------------------------------
# The pre-registered constants. Every one of them is in PREREGISTERED.md; none is chosen
# here, and none may be changed once a model arm has run.
# --------------------------------------------------------------------------------------

TOOL_OUTPUT_BUDGET = 4096
"""Bytes of evidence ids one claim may contribute to the synthesis prompt, for B and C.

The single pre-registered divergence from M19 (``PREREGISTERED.md`` section 1, and the
T2 measurement it rests on in ``reports/m19b/http413/``). It is applied to both model
arms identically and to neither's advantage: arm A never synthesises, so it is
unaffected, and B and C receive the same bound.
"""

FROZEN_TOOL_OUTPUT_BUDGET: dict[str, int | None] = {
    ARM_A: None, ARM_B: TOOL_OUTPUT_BUDGET, ARM_C: TOOL_OUTPUT_BUDGET,
}
"""The value each arm must carry. Asserted at freeze time and again before every run.

Arm A is ``None`` -- the M19 value -- and that is an assertion, not an omission: a
divergence that quietly reached the baseline would make the baseline a different
experiment from the one that produced ``arm_A.json``.
"""

SPECIFIC_MAX_FRACTION = 0.5
"""A recovering claim must cite **fewer than** this fraction of the case's evidence ids.

MEASURED, arm A, T5c: the only claim recovering any pre-registered link today is the
ATT&CK mapper's blanket inference citing 100% of the case's evidence. It satisfies "one
accepted claim cites both sides" while asserting nothing cross-domain at all. This is the
rule that separates the two, fixed before any model arm ran.
"""

SPECIFIC_MAX_IDS = 25
"""...and at most this many ids in total, whatever the case's evidence set looks like.

The fraction alone is not enough: on a case with 600 evidence ids a claim citing 200 of
them is under 50% and is still not a statement about two rows.
"""

SPECIFICITY_RULE = (
    f"an accepted FACT or INFERENCE that cites fewer than "
    f"{SPECIFIC_MAX_FRACTION:.0%} of the case's evidence ids and at most "
    f"{SPECIFIC_MAX_IDS} ids in total"
)

LABELLED_CORPORA_PREFIXES: tuple[str, ...] = ("synthetic:", "dedale_injected:")
"""Corpora with an answer key. ``flaws_cloud`` is real and unlabelled: its completeness,
CDER and stage recovery are UNAVAILABLE rather than 0, and saying so is the measurement.
"""


# --------------------------------------------------------------------------------------
# The arms, and the one divergence
# --------------------------------------------------------------------------------------


def m19b_arm(letter: str) -> ArmConfig:
    """One M19 arm with the pre-registered M19b divergence applied, and nothing else.

    Built from ``ARM_BUILDERS`` -- the same definitions M19 ran -- so an arm's model id,
    budgets, tool surface, planner and synthesis settings are M19's by construction
    rather than by a second declaration that could drift from it.
    """
    arm = ARM_BUILDERS[m19._arm_name(letter)]()
    budget = FROZEN_TOOL_OUTPUT_BUDGET[arm.name]
    if arm.config.tool_output_budget == budget:
        return arm
    return replace(arm, config=replace(arm.config, tool_output_budget=budget))


def m19b_arms() -> list[ArmConfig]:
    return [m19b_arm("A"), m19b_arm("B"), m19b_arm("C")]


def budget_differences(
    arm_configs: Sequence[ArmConfig], expected: dict[str, int | None],
) -> list[str]:
    """Ways the live arms do not carry the pre-registered ``tool_output_budget``.

    Descriptions rather than a boolean, so a refusal names the arm and both values. The
    check has teeth in both directions: it fires if ``InvestigationConfig``'s default
    changes under arm A, and it fires if a later edit removes the bound from B or C.
    """
    differences: list[str] = []
    for arm in arm_configs:
        want = expected.get(arm.name, "(not pre-registered)")
        got = arm.config.tool_output_budget
        if got != want:
            differences.append(
                f"{arm.name}: InvestigationConfig.tool_output_budget is {got!r}, the "
                f"pre-registration fixes {want!r}"
            )
    return differences


def divergence_record(arm_configs: Sequence[ArmConfig]) -> dict[str, Any]:
    """The single divergence from M19, written into the M19b ``ENVIRONMENT.json``.

    One entry, named, with the value each arm actually carries read off the live
    ``ArmConfig`` rather than restated. A freeze that listed an intended value would
    prove nothing about what the run used.
    """
    return {
        "count": 1,
        "field": "InvestigationConfig.tool_output_budget",
        "m19_value": None,
        "m19b_value": {arm.name: arm.config.tool_output_budget for arm in arm_configs},
        "pre_registered": dict(FROZEN_TOOL_OUTPUT_BUDGET),
        "applies_to": [ARM_B, ARM_C],
        "source": "reports/m19b/PREREGISTERED.md section 1; reports/m19b/http413/",
        "reason": (
            "the T2 mitigation. Without it arm B degrades on any case whose tool "
            "results are large; flaws_cloud/CASE-256 carries 108 deterministic facts "
            "from 17 tool calls. The bound changes only how already-verified claim "
            "evidence is rendered for synthesis. Arm A never synthesises and is "
            "unaffected; B and C receive the same bound."
        ),
        "default_unchanged": InvestigationConfig().tool_output_budget is None,
        "agrees_with_live_arms": not budget_differences(
            arm_configs, FROZEN_TOOL_OUTPUT_BUDGET,
        ),
    }


# --------------------------------------------------------------------------------------
# freeze
# --------------------------------------------------------------------------------------


def capture(
    manifest_hash: str, manifest_head: str, *, credential_present: bool = False,
) -> dict[str, Any]:
    """The M19b freeze payload: ``m19b_env``'s assertions plus the divergence.

    ``m19b_env.capture_m19b_environment`` is what asserts equality with M19 on prompts,
    request configuration, retry policy, budgets, model ids and the tool surface, and
    reproduction rather than a hash on scoring. It is called, not re-implemented.
    """
    arm_configs = m19b_arms()
    payload = env19b.capture_m19b_environment(
        ROOT,
        manifest_hash=manifest_hash,
        manifest_head=manifest_head,
        arm_configs=arm_configs,
        credential_present=credential_present,
    )
    payload["divergence"] = divergence_record(arm_configs)
    return payload


def freeze_refusals(payload: dict[str, Any]) -> list[str]:
    """Everything that must hold before an M19b environment may be written."""
    refusals: list[str] = []
    if not payload["m19"]["equal"]:
        refusals += [f"M19 equality: {d}" for d in payload["m19"]["differences"]]
    if not payload["scoring"]["reproduces_grading"]:
        refusals += [f"M19 scoring: {d}" for d in payload["scoring"]["differences"]]
    divergence = payload.get("divergence") or {}
    if not divergence.get("agrees_with_live_arms"):
        # The payload's own verdict is the refusal, whatever a re-check says now: the
        # freeze records what the arms were when it was taken, and a second look that
        # happens to agree does not make the recorded disagreement go away.
        refusals += budget_differences(m19b_arms(), FROZEN_TOOL_OUTPUT_BUDGET) or [
            "divergence: the captured environment reports that the live arms do not "
            "carry the pre-registered tool_output_budget"
        ]
    return refusals


def render_environment_markdown(payload: dict[str, Any]) -> str:
    """``ENVIRONMENT.md``: the divergence first, then ``m19b_env``'s own rendering."""
    divergence = payload.get("divergence") or {}
    values = divergence.get("m19b_value") or {}
    lines = [
        "# M19b ablation: the frozen experiment environment",
        "",
        "## The one pre-registered divergence from M19",
        "",
        f"* field: `{divergence.get('field')}`",
        f"* M19: `{divergence.get('m19_value')}` on every arm",
        "* M19b: " + ", ".join(
            f"`{name}` = `{value}`" for name, value in sorted(values.items())
        ),
        f"* source: {divergence.get('source')}",
        f"* agrees with the live arm definitions: "
        f"{str(divergence.get('agrees_with_live_arms')).lower()}",
        f"* `InvestigationConfig` default still unbounded: "
        f"{str(divergence.get('default_unchanged')).lower()}",
        "",
        f"> {divergence.get('reason')}",
        "",
        "A model arm may not run unless the live `ArmConfig` still carries these "
        "values; see `run`'s refusal.",
        "",
        "---",
        "",
    ]
    return "\n".join(lines) + env19b.render_markdown(payload)


def cmd_freeze(args: argparse.Namespace) -> int:
    import os  # noqa: PLC0415 -- only the credential *presence* is ever read

    payload_manifest, _entries, digest = manifest_script.read_manifest(args.manifest_dir)
    payload = capture(
        digest,
        str(payload_manifest.get("head", "")),
        credential_present=bool(os.getenv(env19b.env.CREDENTIAL_VARIABLE)),
    )
    refusals = freeze_refusals(payload)
    if refusals:
        for refusal in refusals:
            print(f"  {refusal}")
        raise SystemExit(
            "REFUSED to freeze: an M19b environment that is not M19's, a scoring change "
            "that moved an M19 number, or an arm that does not carry the pre-registered "
            "tool_output_budget is not a difference to record -- it is a run to stop."
        )
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_artifact(guarded(out / ENVIRONMENT_JSON), payload)
    write_text(guarded(out / ENVIRONMENT_MD), render_environment_markdown(payload))
    print(f"wrote {out / ENVIRONMENT_JSON}")
    print(f"wrote {out / ENVIRONMENT_MD}")
    print("EQUAL AND REPRODUCING; 1 pre-registered divergence recorded:")
    for name, value in sorted((payload["divergence"]["m19b_value"]).items()):
        print(f"  {name}: tool_output_budget = {value}")
    credential = payload["environment"]["credential"]
    print(f"credential {credential['variable']}: present={credential['present']}")
    return 0


def read_environment(out_dir: Path) -> dict[str, Any]:
    path = out_dir / ENVIRONMENT_JSON
    if not path.exists():
        raise SystemExit(
            f"{path} does not exist. No M19b arm may run before the experiment "
            "environment is frozen: without it nothing afterwards can say whether the "
            "arms shared a prompt, a model id, a tool surface, a budget or a scoring "
            "rule. Run `python scripts/m19b_ablation.py freeze` first."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def guard_arm(arm: ArmConfig, frozen: dict[str, Any], digest: str) -> None:
    """Refuse this arm's run unless the freeze still describes it.

    Two checks, and the second is the one this milestone added. The first is M19's:
    prompts, scoring, model ids, the manifest and the commit, through
    ``environment.check_environment``, and only for an arm that runs a model -- the
    deterministic baseline can be re-run from any commit and produce the same rows,
    which is the property that makes it a baseline.

    The second applies to every arm: the live ``ArmConfig`` and
    ``InvestigationConfig`` must carry the ``tool_output_budget`` the freeze recorded.
    A divergence that is written down and then not enforced is a sentence, not a
    control.
    """
    recorded = dict(frozen.get("divergence") or {}).get("m19b_value") or {}
    expected = recorded or dict(FROZEN_TOOL_OUTPUT_BUDGET)
    differences = budget_differences([arm], expected)
    if differences:
        raise SystemExit(
            "the live arm definition is not the frozen one:\n  "
            + "\n  ".join(differences)
            + "\n\nRefusing to run. The single divergence this experiment pre-registered "
            "is the only one it may carry, and an arm that no longer carries it is a "
            "different arm."
        )
    if not arm.requires_model:
        return
    environment = frozen.get("environment") or {}
    frozen_commit = str(environment.get("git", {}).get("commit", ""))
    live = live_values(
        ROOT, digest, arm_configs=m19b_arms(), frozen_commit=frozen_commit,
    )
    drift = check_environment(environment, live)
    if drift:
        raise SystemExit(
            "the live environment is not the frozen one:\n  "
            + "\n  ".join(drift)
            + "\n\nRefusing to run. Either check out the frozen commit, or freeze again "
            "and say in PREREGISTERED.md what moved and why -- a run under a changed "
            "prompt or a changed scoring rule is a different experiment, not a later "
            "measurement of the same one."
        )
    print(f"environment: matches the freeze at {frozen_commit[:12]}")


# --------------------------------------------------------------------------------------
# The conclusion substrings, derived from the rubric before any run
# --------------------------------------------------------------------------------------

RUBRIC_TEXT_FIELDS: tuple[str, ...] = ("stages", "stage_notes", "next_action")
"""The rubric fields a conclusion substring may be drawn from.

The architect's own words about the case, written into ``MANIFEST.json`` before any
model saw it. ``verdict`` is excluded because it is the answer (``malicious`` /
``benign``) and ``stages_source`` because it is provenance -- a file path whose scenario
name (``scheduled-backup-with-stale-password``) would hand the derivation the answer for
free.

The stage *names* are included alongside the stage notes because they are rubric text of
exactly the same provenance, and because one pre-registered substring -- L2's ``stale``
-- appears only there. The visible consequence is recorded rather than hidden: L1 picks
up ``stale`` as well, which makes L1 harder to discriminate, not easier.
"""

MALICIOUS_PHRASES: tuple[str, ...] = (
    "ADMIN$",
    "LSASS",
    "services.exe",
    "group enumeration",
    "mapped-drive",
    "type 3 logons",
    "service-launched shell",
)
"""Distinguishing facts of a malicious chain, kept for a case whose rubric text says one.

A fixed vocabulary intersected with the case's own rubric text, rather than a per-case
list typed out by hand: what a case pre-registers is then a function of what the
architect wrote about it, and the test that every substring appears in the rubric passes
by construction rather than by inspection.
"""

BENIGN_PHRASES: tuple[str, ...] = ("lock", "unlock", "scheduled", "backup", "stale")
"""The benign explanation, for the two look-alike cases. Same intersection rule.

The pre-registration names ``lock`` / ``unlock`` for L1 and ``scheduled`` / ``backup`` /
``stale`` for L2; this vocabulary is their union, and each case keeps the members its own
rubric text contains.
"""

MALICIOUS_READING: tuple[str, ...] = ("brute", "compromis", "guess")
"""``never_as_fact`` for a benign case: the malicious reading of a look-alike.

Not drawn from the case's rubric, and deliberately so -- these are the words the rubric
says are *wrong* about L1 and L2, so requiring them to appear in it would be incoherent.
They are pre-registered here, in ``PREREGISTERED.md`` section 3, and in the task
statement that fixed them, and they apply only to the benign cases: on a malicious case
the malicious reading is the correct one.
"""

IDENTIFIER_PATTERNS: tuple[tuple[str, str], ...] = (
    ("asset", r"\b[A-Z][A-Z0-9]*[0-9]+\b"),
    ("account", r"\b(?:[a-z][a-z0-9]*_[a-z0-9_]+|[a-z]+[0-9]+)\b"),
    ("address", r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    ("quoted", r"`([^`]+)`"),
)
"""How an identifier is recognised in rubric text: asset names, accounts, addresses, and
anything the architect put in backticks.

Mechanical, and therefore incomplete in a way worth stating: ``jdoe`` in INC-001's next
action is an account name that looks like an ordinary word, and no pattern that caught it
would fail to catch half the sentence. INC-001 still pre-registers ``PC01``,
``svc_backup``, the C2 address and ``LSASS``, which is what "the distinguishing facts"
means for that case.
"""


def rubric_text(rubric: dict[str, Any]) -> str:
    """One case's rubric text: the fields in :data:`RUBRIC_TEXT_FIELDS`, joined."""
    parts: list[str] = []
    for field_name in RUBRIC_TEXT_FIELDS:
        value = rubric.get(field_name)
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            parts += [str(v) for v in value.values()]
        elif isinstance(value, (list, tuple)):
            parts += [str(v) for v in value]
    return " ".join(parts)


def identifiers_in(text: str) -> list[str]:
    """Identifier-shaped tokens in rubric text, deduplicated and sorted."""
    found: set[str] = set()
    for _kind, pattern in IDENTIFIER_PATTERNS:
        for match in re.finditer(pattern, text):
            found.add(match.group(1) if match.groups() else match.group(0))
    return sorted(found)


def substrings_for_case(case: dict[str, Any]) -> dict[str, Any]:
    """One case's ``must_conclude`` / ``never_as_fact``, from its rubric text alone.

    Three verdicts, three rules, all fixed before any run:

    ``malicious``
        the identifiers the rubric names and the distinguishing phrases it uses.
    ``benign``
        the benign explanation only -- the point of a look-alike is whether the arm
        reaches the innocent reading, not whether it can repeat a hostname -- and
        ``never_as_fact`` is the malicious reading.
    ``unknown`` (the two real flaws.cloud cases)
        the identifiers only. There is no answer key, so there is no malicious reading
        to forbid and no benign explanation to require.
    """
    rubric = dict(case.get("rubric") or {})
    verdict = str(rubric.get("verdict", ""))
    text = rubric_text(rubric)
    lowered = text.lower()
    if verdict == "benign":
        must = [p for p in BENIGN_PHRASES if p.lower() in lowered]
        never = list(MALICIOUS_READING)
        rule = "benign explanation only; never_as_fact is the malicious reading"
    elif verdict == "malicious":
        must = identifiers_in(text) + [
            p for p in MALICIOUS_PHRASES if p.lower() in lowered
        ]
        never = []
        rule = "identifiers the rubric names plus the distinguishing phrases it uses"
    else:
        must = identifiers_in(text)
        never = []
        rule = (
            "identifiers only: this corpus is real and unlabelled, so no reading is "
            "pre-registered as right or wrong"
        )
    return {
        "corpus": case["corpus"],
        "case_id": case["case_id"],
        "verdict": verdict or "unknown",
        "must_conclude": sorted(set(must)),
        "never_as_fact": sorted(set(never)),
        "rule": rule,
        "rubric_fields": list(RUBRIC_TEXT_FIELDS),
        "rubric_text": text,
    }


def build_substrings(manifest_payload: dict[str, Any]) -> dict[str, Any]:
    """``RUBRIC_SUBSTRINGS.json``: every case, with the text each was derived from."""
    cases = [substrings_for_case(case) for case in manifest_payload.get("cases", ())]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": m19._head(),
        "manifest_hash": manifest_payload.get("manifest_hash"),
        "benchmark_hash": manifest_payload.get("benchmark_hash"),
        "derived_from": (
            "reports/m19b/MANIFEST.json, the `rubric` block only, fields "
            f"{list(RUBRIC_TEXT_FIELDS)}"
        ),
        "mechanism": (
            "ath.evaluation.incidents.Incident.must_conclude / never_as_fact: a "
            "case-insensitive substring of the joined claim statements, and of the FACT "
            "statements respectively"
        ),
        "vocabularies": {
            "malicious_phrases": list(MALICIOUS_PHRASES),
            "benign_phrases": list(BENIGN_PHRASES),
            "malicious_reading": list(MALICIOUS_READING),
            "identifier_patterns": {kind: p for kind, p in IDENTIFIER_PATTERNS},
        },
        "written_before_any_run": True,
        "cases": {f"{c['corpus']}/{c['case_id']}": c for c in cases},
    }


def read_substrings(path: Path = RUBRIC_SUBSTRINGS_PATH) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(
            f"{path} does not exist. The conclusion substrings are pre-registered: they "
            "are derived from the manifest's rubric text and committed before any arm "
            "runs, because a substring chosen after seeing a model's answer grades the "
            "answer against itself. Run "
            "`python scripts/m19b_ablation.py substrings` first."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def substrings_drift(recorded: dict[str, Any], manifest_payload: dict[str, Any]) -> list[str]:
    """Ways the committed substrings are not what this manifest derives today."""
    rebuilt = build_substrings(manifest_payload)["cases"]
    committed = recorded.get("cases") or {}
    differences: list[str] = []
    for key in sorted(set(rebuilt) | set(committed)):
        want, got = rebuilt.get(key), committed.get(key)
        if want is None or got is None:
            differences.append(f"{key}: present in only one of the two")
            continue
        for field_name in ("must_conclude", "never_as_fact"):
            if list(want[field_name]) != list(got[field_name]):
                differences.append(
                    f"{key}.{field_name}: committed {got[field_name]}, the manifest "
                    f"derives {want[field_name]}"
                )
    return differences


def cmd_substrings(args: argparse.Namespace) -> int:
    payload_manifest, _entries, _digest = manifest_script.read_manifest(args.manifest_dir)
    payload = build_substrings(payload_manifest)
    write_artifact(guarded(Path(args.out)), payload)
    print(f"wrote {args.out}")
    print(link_report.table(
        ["case", "verdict", "must_conclude", "never_as_fact"],
        [
            [key, c["verdict"], ", ".join(c["must_conclude"]) or "--",
             ", ".join(c["never_as_fact"]) or "--"]
            for key, c in payload["cases"].items()
        ],
    ))
    return 0


# --------------------------------------------------------------------------------------
# The oracle: domains and stage membership, read from the answer keys, never by an arm
# --------------------------------------------------------------------------------------


def telemetry_for(corpus: str, external: Path) -> Telemetry:
    """One corpus's telemetry, through the loader that corpus's manifest entry used.

    Telemetry only: the deterministic pipeline is not run, because nothing the oracle
    needs comes from it and flaws.cloud's pipeline is two minutes this does not have to
    spend.
    """
    if corpus.startswith("dedale_injected:"):
        case_id = corpus.split(":", 1)[1]
        return necessity_script._winlogbeat(
            manifest_script.CASE_ROOT / case_id / "winlogbeat"
        )
    if corpus == "flaws_cloud":
        with manifest_script.external_root(external):
            return m19._load_telemetry("flaws_cloud")
    if corpus.startswith("synthetic:"):
        incident_id = corpus.split(":", 1)[1]
        for incident in m19.standard_suite(
            ROOT / "data" / "raw",
            ROOT / "tests" / "fixtures" / "cloudtrail",
            ROOT / "tests" / "fixtures" / "k8s_audit",
        ):
            if incident.incident_id == incident_id:
                return incident.telemetry
        raise SystemExit(f"the standard suite produced no {corpus}")
    raise SystemExit(f"no telemetry loader for corpus {corpus!r}")


def stage_membership(corpus: str, telemetry: Telemetry) -> dict[str, list[str]] | None:
    """``stage name -> the evidence ids labelled to it``, or ``None`` when unlabelled.

    Read through the readers the evaluation layer already owns and that nothing an arm
    touches may use: ``ath.evaluation.external_labels`` for the injected cases -- the
    same ``source_ref`` matching the manifest resolved its links with -- and
    ``load_ground_truth`` for INC-001, whose generator hands out ``event_id`` directly.
    """
    if corpus.startswith("dedale_injected:"):
        case_id = corpus.split(":", 1)[1]
        labels = load_external_labels(
            manifest_script.CASE_ROOT / case_id / "labels.json"
        )
        stages: dict[str, list[str]] = {}
        for scenario in labels.scenarios:
            resolved = resolve_refs(scenario.refs, telemetry)
            for stage in scenario.stages:
                ids = sorted({
                    resolved[ref].event_id for ref in stage.refs
                    if resolved[ref].status == RESOLVED
                })
                stages[stage.name] = ids
        return stages
    if corpus == "synthetic:INC-001":
        truth = load_ground_truth(manifest_script.DATA_RAW)
        return {
            name: sorted(str(e) for e in stage["event_ids"])
            for name, stage in truth["scenarios"]["intrusion"]["stages"].items()
        }
    return None


def build_oracle(
    needed: dict[str, set[str]],
    pinned_hashes: dict[str, str],
    external: Path,
    cache: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Domains for the ids that were cited, and stage membership, per corpus.

    Why it is cached, and what the cache may not hide: resolving a domain means loading
    the corpus, and flaws.cloud is 1.9M rows and three minutes. A cached corpus is reused
    **only** when it already carries a domain for every id the arm files cite and the
    telemetry hash it was built from is still the manifest's -- so a cache can make a
    score faster and cannot make it answer a question it was not asked.
    """
    cached = dict((cache or {}).get("corpora") or {})
    corpora: dict[str, Any] = {}
    for corpus in sorted(needed):
        ids = needed[corpus]
        previous = cached.get(corpus)
        covered = (
            previous is not None
            and previous.get("telemetry_hash") == pinned_hashes.get(corpus)
            and not (ids - set(previous.get("domains") or {}))
            and "stages" in previous
        )
        if covered:
            corpora[corpus] = {**previous, "source": "cache"}
            continue
        started = time.perf_counter()
        telemetry = telemetry_for(corpus, external)
        digest = telemetry_hash(telemetry)
        if pinned_hashes.get(corpus) and digest != pinned_hashes[corpus]:
            raise SystemExit(
                f"{corpus}: the telemetry this oracle loaded hashes to {digest[:12]}, "
                f"the manifest pinned {pinned_hashes[corpus][:12]}. Refusing to resolve "
                "an answer key against a corpus that is not the one the arms ran on."
            )
        domain_of = domain_of_telemetry(telemetry)
        corpora[corpus] = {
            "telemetry_hash": digest,
            "domains": {
                event_id: domain_of(event_id) for event_id in sorted(ids)
                if domain_of(event_id)
            },
            "ids_requested": len(ids),
            "stages": stage_membership(corpus, telemetry),
            "load_seconds": round(time.perf_counter() - started, 1),
            "source": "telemetry",
        }
        print(
            f"oracle {corpus}: {len(corpora[corpus]['domains'])}/{len(ids)} id(s) "
            f"placed in a domain in {corpora[corpus]['load_seconds']}s",
            flush=True,
        )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note": (
            "domains for the ids the arm files cite, and labelled stage membership. "
            "Read from the answer keys by the evaluation layer; no adapter, rule, "
            "specialist or tool ever sees one."
        ),
        "corpora": corpora,
    }


def domain_lookup(oracle: dict[str, Any], corpus: str):
    """``event_id -> domain`` for one corpus, in the shape the T6 metrics consume."""
    domains = dict(((oracle.get("corpora") or {}).get(corpus) or {}).get("domains") or {})

    def domain_of(event_id: str) -> str | None:
        return domains.get(str(event_id))

    return domain_of


# --------------------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------------------


def arm_path(out_dir: Path, letter: str, repeat: int | None = None) -> Path:
    """Where one arm's rows go. ``arm_A.json`` for a single run, ``arm_A_rep2.json``
    for one of several -- so a repeated run never has to decide which of its repeats is
    "the" result by overwriting the other."""
    name = f"arm_{letter}.json" if repeat is None else f"arm_{letter}_rep{repeat}.json"
    return out_dir / name


def required_footing_for(
    arm: ArmConfig, telemetry_digest: str, surface: Sequence[str],
) -> dict[str, Any]:
    """The footing every row of this corpus must match, in T6's own shape.

    Built from the **frozen** tool surface and the **pinned** telemetry hash, so the
    per-row assertion compares what the run is doing against what the freeze and the
    manifest said -- rather than against itself, which is what comparing a row to
    another row of the same run would do.
    """
    return {
        "tool_surface_sha256": sha256_text("\n".join(surface)),
        "tools": len(surface),
        "tool_call_cap": TOOL_CALL_CAP,
        "max_steps": STEP_BUDGET,
        "telemetry_hash": telemetry_digest,
        "requires_model": arm.requires_model,
        "generalist": arm.generalist,
    }


def result_from_row(payload: dict[str, Any]) -> CaseResult:
    """A committed row, read back as a :class:`CaseResult`.

    So that "did this run reproduce the committed one" is answered by
    :func:`~ath.evaluation.ablation.arms.identical` -- the function that already defines
    what two runs of a deterministic arm must agree on -- rather than by a second,
    parallel notion of equality living in this file.
    """
    return CaseResult(
        arm=str(payload["arm"]),
        corpus=str(payload["corpus"]),
        case_id=str(payload["case_id"]),
        manifest_hash=str(payload.get("manifest_hash", "")),
        telemetry_hash=str(payload.get("telemetry_hash", "")),
        configuration=str(payload.get("configuration", "")),
        llm_degraded=bool(payload.get("llm_degraded")),
        llm_status=str(payload.get("llm_status", "")),
        state=dict(payload.get("state") or {}),
        scores=scores_from_dict(payload["scores"]),
        wall_seconds=float(payload.get("wall_seconds") or 0.0),
        tokens=payload.get("tokens"),
        labels=dict(payload.get("labels") or {}),
        label_scores=dict(payload.get("label_scores") or {}),
        budgets=dict(payload.get("budgets") or {}),
        scripted=bool(payload.get("scripted")),
        footing=dict(payload.get("footing") or {}),
        context=dict(payload.get("context") or {}),
    )


T6_ROW_FIELDS: tuple[str, ...] = ("footing", "context")
"""Row fields T6 added after ``arm_A.json`` was written.

Excluded from the reproduction comparison for the same reason wall time is: they did not
exist when the committed rows were produced, so a difference in them is a difference
between two versions of the harness rather than between two investigations.
"""


def _for_reproduction(result: CaseResult) -> CaseResult:
    """A row stripped of exactly what a reproduction claim may not depend on."""
    stripped = replace(result, footing={}, context={})
    stripped.state = m19b_cap(result.state)
    return stripped


def m19b_cap(state: dict[str, Any]) -> dict[str, Any]:
    """The id-capped state, as the file carries it.

    A live row's state is uncapped and the committed one's is capped; comparing them
    without this would report the cap as a difference in the investigation.
    """
    from ath.evaluation.ablation.arms import cap_serialised_ids  # noqa: PLC0415

    return cap_serialised_ids(state)


def reproduction_differences(
    results: Sequence[CaseResult], committed: Sequence[dict[str, Any]],
) -> list[str]:
    """How this arm A run differs from the committed baseline. Empty when it does not."""
    return identical(
        [_for_reproduction(r) for r in results],
        [_for_reproduction(result_from_row(row)) for row in committed],
    )


def cmd_run(args: argparse.Namespace) -> int:
    payload_manifest, entries, digest = manifest_script.read_manifest(args.manifest_dir)
    frozen = read_environment(args.out_dir)
    if frozen.get("environment", {}).get("manifest_hash") not in ("", digest, None):
        raise SystemExit(
            "the frozen environment names manifest "
            f"{str(frozen['environment']['manifest_hash'])[:12]} and this run reads "
            f"{digest[:12]}; freeze against the manifest the run uses."
        )
    recorded_substrings = read_substrings(args.substrings)
    drift = substrings_drift(recorded_substrings, payload_manifest)
    if drift:
        raise SystemExit(
            "the committed conclusion substrings are not what this manifest derives:\n  "
            + "\n  ".join(drift)
            + "\n\nRefusing to run: they are pre-registered, so either the manifest or "
            "the derivation moved, and both are changes to the experiment."
        )

    letter = m19._arm_letter(args.arm)
    arm = m19b_arm(letter)
    guard_arm(arm, frozen, digest)

    surface = list(
        (frozen.get("environment") or {}).get("shared_tool_surface") or tool_surface()
    )
    by_corpus: dict[str, list[CaseManifest]] = defaultdict(list)
    for entry in entries:
        by_corpus[entry.corpus].append(entry)

    runs: list[list[CaseResult]] = [[] for _ in range(args.repeat)]
    timing: dict[str, Any] = {}
    for bundle in manifest_script.bundles(args.external):
        corpus_entries = by_corpus.get(bundle.name)
        if not corpus_entries:
            continue
        footing = required_footing_for(arm, corpus_entries[0].telemetry_hash, surface)
        started = time.perf_counter()
        for index in range(args.repeat):
            runs[index] += run_arm(
                arm, corpus_entries, bundle.telemetry, bundle.cases,
                manifest_digest=digest, findings=bundle.findings,
                environment=bundle.environment,
                label_scorer=m19._label_scorer(bundle),
                required_footing=footing,
            )
        timing[bundle.name] = {
            "load_seconds": round(bundle.load_seconds, 1),
            "pipeline_seconds": round(bundle.pipeline_seconds, 1),
            "arm_seconds_all_repeats": round(time.perf_counter() - started, 1),
            "cases": len(corpus_entries),
        }
        print(
            f"{bundle.name}: {len(corpus_entries)} case(s) x {args.repeat} run(s) in "
            f"{timing[bundle.name]['arm_seconds_all_repeats']}s",
            flush=True,
        )

    differences = identical(runs[0], runs[-1]) if args.repeat > 1 else []
    if args.repeat > 1 and differences and not arm.requires_model:
        raise SystemExit(
            f"{arm.name} is deterministic and its {args.repeat} runs differ in "
            f"{len(differences)} place(s): {differences[:5]}. A baseline that is not "
            "reproducible cannot be the baseline anything is compared against."
        )

    reproduction: dict[str, Any] = {"compared_against": None}
    baseline_path = args.out_dir / "arm_A.json"
    if letter == "A" and baseline_path.exists():
        committed = json.loads(baseline_path.read_text(encoding="utf-8"))["cases"]
        drifted = reproduction_differences(runs[0], committed)
        reproduction = {
            "compared_against": rel(baseline_path),
            "rows": len(committed),
            "excluded": ["wall_seconds", "started_at", "called_at", *T6_ROW_FIELDS],
            "reproduces": not drifted,
            "differences": drifted,
        }
        if drifted:
            raise SystemExit(
                f"this arm A run does not reproduce {baseline_path.name} in "
                f"{len(drifted)} place(s): {drifted[:5]}. The deterministic baseline is "
                "the fixed point every model arm is read against; a baseline that moved "
                "is a defect to report, not a run to keep."
            )
        print(f"reproduction: IDENTICAL to {baseline_path.name} ({len(committed)} rows)")

    header = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": m19._head(),
        "harness": "scripts/m19b_ablation.py",
        "arm": arm.to_dict(),
        "tool_output_budget": arm.config.tool_output_budget,
        "scripted": False,
        "manifest_hash": digest,
        "manifest_head": payload_manifest.get("head"),
        "benchmark_hash": payload_manifest.get("benchmark_hash"),
        "environment": rel(args.out_dir / ENVIRONMENT_JSON),
        "rubric_substrings": rel(Path(args.substrings)),
        "required_footing_checked": True,
        "reproducibility": {
            "repeats": args.repeat,
            "compared": args.repeat > 1,
            "identical": args.repeat > 1 and not differences,
            "differences": differences,
            "note": (
                "wall seconds and wall-clock timestamps are excluded from the "
                "comparison; every claim, tool call, plan-log line and score is included"
            ),
        },
        "reproduction_of_t5c_baseline": reproduction,
        "budgets": {
            "max_steps": arm.config.max_steps,
            "tool_call_cap": arm.tool_call_cap,
            "cases_hitting_tool_cap": sum(
                1 for r in runs[0] if r.budgets.get("tool_budget_hit")
            ),
            "cases_hitting_step_budget": sum(
                1 for r in runs[0] if r.budgets.get("step_budget_hit")
            ),
        },
        "timing": timing,
    }

    written: list[Path] = []
    for index, rows in enumerate(runs, start=1):
        out = arm_path(args.out_dir, letter, None if args.repeat == 1 else index)
        m19.refuse_mislabelled_output(out, rows)
        write_artifact(guarded(out), {**header, "repeat": index, "cases": [r.to_dict() for r in rows]})
        written.append(out)
        print(f"wrote {out} ({len(rows)} row(s))")

    if args.check_planner:
        lines, failures = m19.planner_report(runs[0], arm.requires_model)
        print("planner accounting:")
        for line in lines:
            print(f"  {line}")
        if failures:
            print(
                f"PLANNER CHECK FAILED: {len(failures)} row(s) labelled as a model arm "
                "planned deterministically:"
            )
            for failure in failures:
                print(f"  {failure}")
            return 1
        print("planner check: no model-arm row planned deterministically")
    return 0


# --------------------------------------------------------------------------------------
# score
# --------------------------------------------------------------------------------------


def cited(claim: dict[str, Any]) -> set[str]:
    return {str(e) for e in (claim.get("evidence_ids") or ())}


def is_specific(cited_ids: set[str], case_evidence: set[str]) -> bool:
    """The pre-registered specificity rule. See :data:`SPECIFICITY_RULE`.

    Two bounds, both of which must hold: at most :data:`SPECIFIC_MAX_IDS` ids, and fewer
    than :data:`SPECIFIC_MAX_FRACTION` of the case's own evidence. The fraction is over
    the case's evidence set rather than over the claim's citations, because the question
    it answers is "did this claim single anything out" -- a claim citing the whole case
    has singled nothing out however many ids that happens to be.
    """
    if len(cited_ids) > SPECIFIC_MAX_IDS:
        return False
    if case_evidence:
        share = len(cited_ids & case_evidence) / len(case_evidence)
        if share >= SPECIFIC_MAX_FRACTION:
            return False
    return True


def specific_claims(payload: dict[str, Any], case_evidence: set[str]) -> list[dict[str, Any]]:
    return [
        claim for claim in payload.get("claims", ())
        if isinstance(claim, dict)
        and claim.get("type") in RECOVERING_CLAIM_TYPES
        and is_specific(cited(claim), case_evidence)
    ]


def specific_payload(payload: dict[str, Any], case_evidence: set[str]) -> dict[str, Any]:
    """The same investigation with only its *specific* accepted claims.

    Handing this to the T6 metrics is how the specificity rule reaches them without a
    second copy of CDER or of UCC living here: those functions already answer "what did
    these claims recover", and this decides which claims are allowed to answer.
    """
    return {**payload, "claims": specific_claims(payload, case_evidence)}


def link_pairs(case: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (str(link["identity"]["event_id"]), str(link["endpoint"]["event_id"]))
        for link in case.get("links") or ()
    ]


def link_ids_by_pair(case: dict[str, Any]) -> dict[frozenset, str]:
    return {
        frozenset({str(link["identity"]["event_id"]), str(link["endpoint"]["event_id"])}):
            str(link["link_id"])
        for link in case.get("links") or ()
    }


def cder(
    payload: dict[str, Any], case: dict[str, Any], case_evidence: set[str], domain_of: Any,
) -> dict[str, Any]:
    """CDER-specific and CDER-blanket for one row.

    Both are :func:`cross_domain_evidence_recovery` -- the T6 definition, unchanged --
    run twice: once over every accepted claim and once over the specific ones. What the
    first recovers and the second does not is a **blanket** recovery: a claim that cites
    both sides of the link because it cites everything. Reported, never credited.
    """
    pairs = link_pairs(case)
    if not pairs:
        # The same keys as a defined case, so a reader joining the nine rows into one
        # table does not have to special-case the two that have no answer key. The
        # zeros are not scores: `status` says UNAVAILABLE and `defined` is 0.
        return {
            "status": str(case.get("cder", "UNAVAILABLE")),
            "defined": 0, "specific_recovered": 0, "specific": None,
            "specific_link_ids": [], "any_recovered": 0,
            "blanket_recovered": 0, "blanket_link_ids": [],
            "rule": SPECIFICITY_RULE,
            "note": "no link is pre-registered on an unlabelled corpus",
        }
    names = link_ids_by_pair(case)
    everything = cross_domain_evidence_recovery(payload, pairs, domain_of)
    specific = cross_domain_evidence_recovery(
        specific_payload(payload, case_evidence), pairs, domain_of,
    )

    def named(recovery: dict[str, Any]) -> list[str]:
        return sorted(
            names[frozenset(link["evidence_ids"])]
            for link in recovery["recovered_links"]
        )

    all_ids, specific_ids = named(everything), named(specific)
    blanket = sorted(set(all_ids) - set(specific_ids))
    return {
        "status": str(case.get("cder", "")),
        "defined": len(pairs),
        "specific_recovered": len(specific_ids),
        "specific": round(len(specific_ids) / len(pairs), 4),
        "specific_link_ids": specific_ids,
        "any_recovered": len(all_ids),
        "blanket_recovered": len(blanket),
        "blanket_link_ids": blanket,
        "rule": SPECIFICITY_RULE,
        "note": "blanket recoveries are reported and never credited",
    }


def stage_recovery(
    payload: dict[str, Any], stages: dict[str, list[str]] | None, case_evidence: set[str],
) -> dict[str, Any]:
    """Which rubric stages a specific accepted claim reached.

    A stage is recovered when one specific accepted claim cites at least one evidence id
    labelled to it. One id, not two: a stage is a place in the story, and citing a row
    that belongs to it is what reaching it means. The *link* metric is where joining two
    of them is required.
    """
    if stages is None:
        return {"status": "UNAVAILABLE (unlabelled corpus)", "defined": 0,
                "recovered": 0, "recovered_stages": [], "missed_stages": []}
    claims = specific_claims(payload, case_evidence)
    cited_ids: set[str] = set()
    for claim in claims:
        cited_ids |= cited(claim)
    recovered = sorted(
        name for name, ids in stages.items() if cited_ids & {str(i) for i in ids}
    )
    return {
        "status": "DEFINED",
        "defined": len(stages),
        "recovered": len(recovered),
        "recovered_stages": recovered,
        "missed_stages": sorted(set(stages) - set(recovered)),
        "specific_claims": len(claims),
    }


def completeness(cder_block: dict[str, Any], stage_block: dict[str, Any], labelled: bool):
    """H1's ratio: (specific links recovered + stages recovered) / (links + stages).

    ``None`` -- UNAVAILABLE -- for the two real cases, which have neither links nor
    stages. A case with no answer key does not score 0 on a metric about recovering an
    answer key; it is not on the scale.
    """
    if not labelled:
        return {"status": "UNAVAILABLE (real, unlabelled corpus)", "value": None,
                "numerator": None, "denominator": None}
    numerator = cder_block["specific_recovered"] + stage_block["recovered"]
    denominator = cder_block["defined"] + stage_block["defined"]
    return {
        "status": "DEFINED",
        "value": round(numerator / denominator, 4) if denominator else None,
        "numerator": numerator,
        "denominator": denominator,
    }


def conclusion_scores(
    payload: dict[str, Any], must_conclude: Sequence[str], never_as_fact: Sequence[str],
) -> dict[str, Any]:
    """``must_conclude`` / ``never_as_fact``, exactly as ``incidents.score_labels`` reads
    them: a case-insensitive substring of the joined claim statements, and of the joined
    FACT statements respectively.

    Implemented over a serialised payload rather than a live
    :class:`~ath.agent.state.InvestigationState`, which is the only reason it is not a
    direct call; ``tests/test_m19b_ablation.py`` asserts the two agree on a constructed
    state, so the rule has one meaning in this repository.
    """
    claims = [c for c in payload.get("claims", ()) if isinstance(c, dict)]
    statements = " ".join(str(c.get("statement", "")) for c in claims).lower()
    facts = " ".join(
        str(c.get("statement", "")) for c in claims if c.get("type") == "FACT"
    ).lower()
    hit = [phrase for phrase in must_conclude if phrase.lower() in statements]
    overclaimed = [phrase for phrase in never_as_fact if phrase.lower() in facts]
    return {
        "must_conclude": list(must_conclude),
        "conclusions_hit": hit,
        "conclusions_missed": [p for p in must_conclude if p not in hit],
        "never_as_fact": list(never_as_fact),
        "overclaimed_as_fact": overclaimed,
    }


def discrimination(
    conclusions: dict[str, Any], verdict: str,
) -> dict[str, Any]:
    """Whether a benign look-alike was told apart from the attack it imitates.

    Defined for a benign case only, and both halves are required: the arm's claims carry
    the benign explanation, **and** no FACT asserts the malicious reading. An arm that
    says "scheduled backup" and also asserts, as fact, that a credential was guessed has
    not discriminated anything -- it has said both things.
    """
    if verdict != "benign":
        return {"status": "NOT APPLICABLE (not a benign look-alike)", "discriminated": None}
    explained = not conclusions["conclusions_missed"]
    overclaimed = bool(conclusions["overclaimed_as_fact"])
    return {
        "status": "DEFINED",
        "discriminated": bool(explained and not overclaimed),
        "benign_explanation_present": explained,
        "benign_substrings_missed": conclusions["conclusions_missed"],
        "malicious_reading_as_fact": conclusions["overclaimed_as_fact"],
    }


def rubric_for(
    case: dict[str, Any], stages: dict[str, list[str]] | None, domain_of: Any,
) -> CaseRubric:
    """The T6 rubric for one case: its links, and its stages as "matters" items.

    A ``verdict`` item is registered over the union of the pre-registered link ids,
    because the manifest's condition 3 says in words what that set says in ids: the
    verdict on these cases turns on the cross-domain join. ``next_action`` registers no
    item -- the manifest pre-registers its *text*, and no evidence ids for it, and a
    rubric item with no ids maps nothing.
    """
    items: list[RubricItem] = []
    for name, ids in (stages or {}).items():
        items.append(RubricItem(
            name=name, kind="stage", evidence_ids=frozenset(str(i) for i in ids),
        ))
    link_evidence = {e for pair in link_pairs(case) for e in pair}
    if link_evidence:
        items.append(RubricItem(
            name="verdict", kind="verdict", evidence_ids=frozenset(link_evidence),
        ))
    return CaseRubric(
        case_id=str(case["case_id"]),
        links=tuple(link_pairs(case)),
        items=tuple(items),
        domain_of=domain_of,
    )


HTTP_STATUS = re.compile(r"^HTTP (\d+|\?)")


def reliability(row: dict[str, Any]) -> dict[str, Any]:
    """What went wrong during this row, counted by kind rather than summarised.

    Error *type* and *message* separately, because M19b needed both: every model call in
    one robustness run failed with ``HTTP 400 (the request was rejected as malformed)``
    and the request was fine -- the account's balance was exhausted, which only the
    provider's own ``error.type`` and ``error.message`` said.
    """
    llm = dict((row.get("state") or {}).get("llm") or {})
    errors = [str(e) for e in (llm.get("errors") or ())]
    statuses: Counter = Counter()
    types: Counter = Counter()
    for error in errors:
        match = HTTP_STATUS.match(error)
        statuses[match.group(1) if match else "(not an HTTP error)"] += 1
        detail = error.split("; ", 1)[1] if "; " in error else ""
        types[detail.split(":", 1)[0] if detail else "(no provider detail)"] += 1
    budgets = dict(row.get("budgets") or {})
    return {
        "model_errors": len(errors),
        "http_status_counts": dict(sorted(statuses.items())),
        "provider_error_type_counts": dict(sorted(types.items())),
        "error_message_counts": dict(sorted(Counter(errors).items())),
        "truncations": sum(1 for e in errors if "truncated at max_tokens" in e),
        "textless_replies": sum(1 for e in errors if "no text block" in e),
        "parse_failures": int(llm.get("unparseable_responses", 0)),
        "parse_failures_by_kind": dict(llm.get("unparseable_by_kind") or {}),
        "degraded": bool(row.get("llm_degraded")),
        "llm_status": str(row.get("llm_status", "")),
        "tool_budget_hit": bool(budgets.get("tool_budget_hit")),
        "step_budget_hit": bool(budgets.get("step_budget_hit")),
        "tool_calls_refused": int(budgets.get("tool_calls_refused", 0)),
    }


def is_labelled(corpus: str) -> bool:
    return corpus.startswith(LABELLED_CORPORA_PREFIXES)


def new_evidence(payload: dict[str, Any], baseline_claim_ids: set[str], baseline_all: set[str]):
    """Hypotheses citing evidence arm A's claims did not cite. M19's rule, unchanged."""
    hypotheses = [
        c for c in payload.get("claims", ())
        if isinstance(c, dict) and c.get("type") == "HYPOTHESIS"
    ]
    return {
        "hypotheses": len(hypotheses),
        "hypotheses_citing_evidence_A_claims_did_not": sum(
            1 for h in hypotheses if cited(h) - baseline_claim_ids
        ),
        "hypotheses_citing_evidence_A_never_touched": sum(
            1 for h in hypotheses if cited(h) - baseline_all
        ),
    }


def claim_and_tool_ids(payload: dict[str, Any]) -> tuple[set[str], set[str]]:
    claims: set[str] = set()
    for claim in payload.get("claims", ()):
        if isinstance(claim, dict):
            claims |= cited(claim)
    tools: set[str] = set()
    for result in payload.get("results", ()):
        for call in result.get("tool_calls", ()):
            tools |= {str(e) for e in (call.get("event_ids") or ())}
    return claims, claims | tools


def resolve_rows(out_dir: Path, letter: str, override: Path | None) -> Path:
    """Which file this arm's rows are read from, and the order that is decided in.

    A repeated run's first repeat is preferred over a single-run file of the same name,
    because the repeats are this harness's rows and ``arm_A.json`` is T5c's -- written
    before the fields these metrics read existed.
    """
    if override is not None:
        return override
    for candidate in (arm_path(out_dir, letter, 1), arm_path(out_dir, letter)):
        if candidate.exists():
            return candidate
    raise SystemExit(
        f"no rows for arm {letter} under {out_dir}: expected "
        f"{arm_path(out_dir, letter, 1).name} or {arm_path(out_dir, letter).name}. "
        "Run the arm first."
    )


def cmd_score(args: argparse.Namespace) -> int:
    payload_manifest, _entries, digest = manifest_script.read_manifest(args.manifest_dir)
    substrings = read_substrings(args.substrings)
    letter = m19._arm_letter(args.arm)
    source = resolve_rows(args.out_dir, letter, args.rows)
    rows = json.loads(source.read_text(encoding="utf-8"))["cases"]
    cases = {f"{c['corpus']}/{c['case_id']}": c for c in payload_manifest["cases"]}

    baseline_path = args.arm_a if args.arm_a is not None else args.out_dir / "arm_A.json"
    baseline_rows = {
        f"{r['corpus']}/{r['case_id']}": r
        for r in json.loads(baseline_path.read_text(encoding="utf-8"))["cases"]
    }

    needed: dict[str, set[str]] = defaultdict(set)
    pinned: dict[str, str] = {}
    for row in rows:
        payload = state_payload(row)
        claims, _everything = claim_and_tool_ids(payload)
        needed[row["corpus"]] |= claims
        pinned[row["corpus"]] = str(row.get("telemetry_hash", ""))
    for case in cases.values():
        needed[case["corpus"]] |= {str(e) for e in case["evidence_ids"]}
        needed[case["corpus"]] |= {e for pair in link_pairs(case) for e in pair}
    cache = (
        json.loads(ORACLE_PATH.read_text(encoding="utf-8"))
        if ORACLE_PATH.exists() and not args.no_oracle_cache else None
    )
    oracle = build_oracle(dict(needed), pinned, args.external, cache)
    write_artifact(guarded(ORACLE_PATH), oracle)

    scored: list[dict[str, Any]] = []
    aggregate_rows: list[Any] = []
    for row in rows:
        key = f"{row['corpus']}/{row['case_id']}"
        case = cases[key]
        payload = state_payload(row)
        domain_of = domain_lookup(oracle, row["corpus"])
        stages = ((oracle["corpora"].get(row["corpus"]) or {}).get("stages"))
        case_evidence = {str(e) for e in case["evidence_ids"]}
        labelled = is_labelled(row["corpus"])

        cder_block = cder(payload, case, case_evidence, domain_of)
        stage_block = stage_recovery(payload, stages, case_evidence)
        pre = substrings["cases"][key]
        conclusions = conclusion_scores(
            payload, pre["must_conclude"], pre["never_as_fact"],
        )
        baseline = baseline_rows.get(key)
        baseline_claims, baseline_all = (
            claim_and_tool_ids(state_payload(baseline)) if baseline else (set(), set())
        )
        specific = specific_payload(payload, case_evidence)
        ucc = unique_cross_domain_contribution(
            {row["arm"]: specific}, rubric_for(case, stages, domain_of),
        )[row["arm"]]
        cross_domain = cross_domain_claims(specific, domain_of)

        aggregate_rows.append(m19._Row(
            labelled_arm=str(row["labelled_arm"]), corpus=str(row["corpus"]),
            case_id=str(row["case_id"]), llm_degraded=bool(row["llm_degraded"]),
            scores=scores_from_dict(row["scores"]),
        ))
        scored.append({
            "case": key,
            "corpus": row["corpus"],
            "case_id": row["case_id"],
            "arm": row["arm"],
            "labelled_arm": row["labelled_arm"],
            "labelled_corpus": labelled,
            "verdict": pre["verdict"],
            "m19": row["scores"],
            "cder": cder_block,
            "stages": stage_block,
            "completeness_h1": completeness(cder_block, stage_block, labelled),
            "conclusions": conclusions,
            "discrimination": discrimination(conclusions, pre["verdict"]),
            "cross_domain_claims_specific": {
                "count": cross_domain["verified_count"],
                "by_type": cross_domain["by_type"],
                "domain_pairs": cross_domain["domain_pairs"],
            },
            "ucc": {k: v for k, v in ucc.items() if k != "entries"},
            "ucc_entries": ucc["entries"],
            "new_evidence_vs_arm_A": new_evidence(payload, baseline_claims, baseline_all),
            "planner": planner_activation(payload),
            "duplicate_tool_calls": duplicate_tool_calls(payload),
            "context": row.get("context") or context_size(payload),
            "cost": {
                "tokens": row.get("tokens"),
                "wall_seconds": row.get("wall_seconds"),
                "model_calls": (row.get("context") or context_size(payload)).get(
                    "model_calls", 0
                ),
            },
            "reliability": reliability(row),
        })

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": m19._head(),
        "harness": "scripts/m19b_ablation.py",
        "arm": letter,
        "rows_from": rel(source),
        "arm_a_baseline": rel(baseline_path),
        "manifest_hash": digest,
        "rubric_substrings": rel(Path(args.substrings)),
        "constants": {
            "SPECIFIC_MAX_FRACTION": SPECIFIC_MAX_FRACTION,
            "SPECIFIC_MAX_IDS": SPECIFIC_MAX_IDS,
            "TOOL_OUTPUT_BUDGET": TOOL_OUTPUT_BUDGET,
            "rule": SPECIFICITY_RULE,
        },
        "ucc_note": (
            "computed over this arm alone; `grade` recomputes it across every arm that "
            "ran, which is the only way uniqueness can be decided"
        ),
        "m19_summary": aggregate(aggregate_rows),
        "cases": scored,
    }
    out = args.out_dir / f"scores_{letter}.json"
    write_artifact(guarded(out), payload)
    print(f"wrote {out}")
    print(score_table(scored))
    return 0


def score_table(scored: Sequence[dict[str, Any]]) -> str:
    return link_report.table(
        ["case", "CDER-specific", "CDER-blanket", "stages", "completeness",
         "planner choice steps", "duplicate calls", "specific x-domain claims"],
        [
            [
                row["case"],
                f"{row['cder']['specific_recovered']}/{row['cder']['defined']}"
                if row["cder"]["defined"] else row["cder"].get("status", "--"),
                row["cder"]["blanket_recovered"] if row["cder"]["defined"] else "--",
                f"{row['stages']['recovered']}/{row['stages']['defined']}"
                if row["stages"]["defined"] else "UNAVAILABLE",
                row["completeness_h1"]["value"]
                if row["completeness_h1"]["value"] is not None else "UNAVAILABLE",
                f"{row['planner']['chosen_by_model']}/"
                f"{row['planner']['multi_candidate_steps']}",
                row["duplicate_tool_calls"]["duplicate_calls"],
                row["cross_domain_claims_specific"]["count"],
            ]
            for row in scored
        ],
    )


# --------------------------------------------------------------------------------------
# grade
# --------------------------------------------------------------------------------------

ARM_LETTERS = {"A": ARM_A, "B": ARM_B, "C": ARM_C}


def _by_case(scores: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["case"]: row for row in scores.get("cases", ())}


def _wins(rows_x: dict[str, Any], rows_y: dict[str, Any], read) -> dict[str, Any]:
    """Cases where ``x`` is strictly greater than ``y``, with the numbers behind it."""
    per_case = []
    for key in sorted(set(rows_x) & set(rows_y)):
        left, right = read(rows_x[key]), read(rows_y[key])
        per_case.append({
            "case": key, "x": left, "y": right,
            "x_greater": left is not None and right is not None and left > right,
        })
    return {
        "cases": len(per_case),
        "x_greater_on": sum(1 for p in per_case if p["x_greater"]),
        "per_case": per_case,
    }


def _mean(values: Sequence[float]):
    return round(statistics.mean(values), 4) if values else None


def _median(values: Sequence[float]):
    return round(statistics.median(values), 4) if values else None


def grade_hypotheses(by_arm: dict[str, dict[str, dict[str, Any]]]) -> dict[str, Any]:
    """H1-H6, exactly by the rules in ``PREREGISTERED.md`` section 4.

    Every number here is an integer, a ratio of integers, or a duration. Nothing reads a
    statement, a summary or a ranking: the grader cannot be flattered by a well-written
    answer, which is the property the plan's rule 5 asks for.
    """
    A, B, C = by_arm.get("A", {}), by_arm.get("B", {}), by_arm.get("C", {})
    grades: dict[str, Any] = {}

    labelled = sorted(k for k, row in (C or B).items() if row["labelled_corpus"])
    h1 = _wins(
        {k: C[k] for k in labelled if k in C},
        {k: B[k] for k in labelled if k in B},
        lambda row: row["completeness_h1"]["value"],
    )
    grades["H1"] = {
        "statement": "C outperforms B on investigation completeness",
        "rule": "C's per-case completeness > B's on >= 5 of 7 labelled cases",
        "prediction": "FALSE",
        "labelled_cases": len(labelled),
        "threshold": 5,
        "C_greater_on": h1["x_greater_on"],
        "holds": h1["x_greater_on"] >= 5,
        "per_case": h1["per_case"],
    }

    h2 = _wins(C, B, lambda row: row["cross_domain_claims_specific"]["count"])
    grades["H2"] = {
        "statement": "C combines cross-domain evidence more often than B",
        "rule": "count of specific cross-domain claims, C > B on >= 5 of 9 cases",
        "prediction": "FALSE",
        "threshold": 5,
        "C_greater_on": h2["x_greater_on"],
        "holds": h2["x_greater_on"] >= 5,
        "per_case": h2["per_case"],
    }

    tokens = {
        arm: [
            row["cost"]["tokens"] for row in rows.values()
            if isinstance(row["cost"]["tokens"], (int, float))
        ]
        for arm, rows in (("B", B), ("C", C))
    }
    median_b, median_c = _median(tokens["B"]), _median(tokens["C"])
    grades["H3"] = {
        "statement": "C needs fewer tokens than B",
        "rule": "median tokens per case C < 0.5 x B",
        "prediction": "TRUE",
        "median_tokens_B": median_b,
        "median_tokens_C": median_c,
        "half_of_B": round(median_b * 0.5, 4) if median_b is not None else None,
        "holds": (
            median_b is not None and median_c is not None and median_c < 0.5 * median_b
        ),
        "rows_reporting_tokens": {arm: len(v) for arm, v in tokens.items()},
    }

    duplicates = {
        arm: [row["duplicate_tool_calls"]["duplicate_calls"] for row in rows.values()]
        for arm, rows in (("B", B), ("C", C))
    }
    walls = {
        arm: [
            row["cost"]["wall_seconds"] for row in rows.values()
            if isinstance(row["cost"]["wall_seconds"], (int, float))
        ]
        for arm, rows in (("B", B), ("C", C))
    }
    dup_wins = _wins(C, B, lambda row: row["duplicate_tool_calls"]["duplicate_calls"])
    wall_wins = _wins(C, B, lambda row: row["cost"]["wall_seconds"])
    dup_holds = (
        _mean(duplicates["C"]) is not None and _mean(duplicates["B"]) is not None
        and _mean(duplicates["C"]) > _mean(duplicates["B"])
    )
    wall_holds = (
        _mean(walls["C"]) is not None and _mean(walls["B"]) is not None
        and _mean(walls["C"]) > _mean(walls["B"])
    )
    grades["H4"] = {
        "statement": "C incurs coordination overhead in latency and duplicated calls",
        "holds": f"duplication={dup_holds}, latency={wall_holds}",
        "rule": (
            "duplicate calls per case C > B; wall seconds per case C > B -- graded "
            "separately, on the mean per case, with the per-case win counts beside it"
        ),
        "prediction": "TRUE for duplication, FALSE for latency",
        "duplication": {
            "mean_per_case_B": _mean(duplicates["B"]),
            "mean_per_case_C": _mean(duplicates["C"]),
            "median_per_case_B": _median(duplicates["B"]),
            "median_per_case_C": _median(duplicates["C"]),
            "cases_C_greater": dup_wins["x_greater_on"],
            "holds": dup_holds,
            "per_case": dup_wins["per_case"],
        },
        "latency": {
            "mean_per_case_B": _mean(walls["B"]),
            "mean_per_case_C": _mean(walls["C"]),
            "median_per_case_B": _median(walls["B"]),
            "median_per_case_C": _median(walls["C"]),
            "cases_C_greater": wall_wins["x_greater_on"],
            "holds": wall_holds,
            "per_case": wall_wins["per_case"],
        },
    }

    def with_new_evidence(rows: dict[str, Any]) -> list[str]:
        return sorted(
            key for key, row in rows.items()
            if row["new_evidence_vs_arm_A"][
                "hypotheses_citing_evidence_A_claims_did_not"
            ]
        )

    new_b, new_c = with_new_evidence(B), with_new_evidence(C)
    grades["H5"] = {
        "statement": "B remains better at discovering evidence outside predefined scopes",
        "rule": "cases with >= 1 new-evidence hypothesis: B > C",
        "prediction": "TRUE",
        "cases_B": len(new_b), "cases_C": len(new_c),
        "case_ids_B": new_b, "case_ids_C": new_c,
        "holds": len(new_b) > len(new_c),
    }

    per_arm_h6 = {}
    for arm, rows in by_arm.items():
        bad_ec = sorted(k for k, r in rows.items() if r["m19"]["evidence_correctness"] != 1.0)
        rejected = sorted(k for k, r in rows.items() if r["m19"]["rejected_claims"])
        per_arm_h6[ARM_LETTERS.get(arm, arm)] = {
            "rows": len(rows),
            "rows_below_1.0_evidence_correctness": bad_ec,
            "rows_with_rejected_claims": rejected,
            "holds": not bad_ec and not rejected,
        }
    grades["H6"] = {
        "statement": "All factual claims stay evidence-grounded in every arm",
        "rule": "evidence correctness 1.0 and 0 rejected claims on every row",
        "prediction": "TRUE",
        "per_arm": per_arm_h6,
        "holds": all(v["holds"] for v in per_arm_h6.values()),
    }
    return grades


def decision_rule(
    by_arm: dict[str, dict[str, dict[str, Any]]],
    grades: dict[str, Any],
    ucc: dict[str, dict[str, int]],
    triggers: dict[str, bool],
) -> dict[str, Any]:
    """Section 5, evaluated mechanically. Read only after H1-H6 are graded."""
    A, B, C = by_arm.get("A", {}), by_arm.get("B", {}), by_arm.get("C", {})
    keys = sorted(set(B) & set(C))
    # Every branch of section 5 is a comparison between the two model arms. With one of
    # them missing the rule has no input, and answering anyway would let a partial run
    # select an outcome -- which is precisely the mistake "no row is rerun" exists to
    # prevent, arriving through the back door.
    comparable = bool(B) and bool(C)

    ucc_c_ge_b = [k for k in keys if ucc["C"].get(k, 0) >= ucc["B"].get(k, 0)]
    ucc_c_gt_b = [k for k in keys if ucc["C"].get(k, 0) > ucc["B"].get(k, 0)]
    ucc_b_gt_c = [k for k in keys if ucc["B"].get(k, 0) > ucc["C"].get(k, 0)]
    hybrid_cases = [k for k in ucc_c_gt_b if triggers.get(k)]

    def adds_over_a(rows: dict[str, Any], key: str) -> bool:
        """Did this model arm add a specific link, a UCC or a discrimination A lacked."""
        row, baseline = rows.get(key), A.get(key)
        if row is None or baseline is None:
            return False
        if row["cder"]["specific_recovered"] > baseline["cder"]["specific_recovered"]:
            return True
        if row["ucc"]["unique_and_matters"] > 0:
            return True
        return bool(
            row["discrimination"].get("discriminated")
            and not baseline["discrimination"].get("discriminated")
        )

    have_baseline = bool(A)
    adds = {
        arm: sorted(k for k in keys if adds_over_a(rows, k)) if have_baseline else None
        for arm, rows in (("B", B), ("C", C))
    }
    majority = (len(keys) // 2) + 1
    neither_adds = have_baseline and (
        len(adds["B"]) < majority and len(adds["C"]) < majority
    )

    degraded = {
        arm: sum(1 for row in rows.values() if row["reliability"]["degraded"])
        for arm, rows in (("B", B), ("C", C))
    }

    crew_adds_nothing = (
        comparable and have_baseline and bool(keys)
        and all(not adds_over_a(C, k) for k in keys)
    )

    keep = bool(grades["H1"]["holds"] and len(ucc_c_ge_b) >= 5 and grades["H6"]["holds"])
    hybrid = len(hybrid_cases) >= 3
    single = bool(
        grades["H5"]["holds"]
        and len(ucc_b_gt_c) > len(ucc_c_gt_b)
        and grades["H6"]["holds"]
        and degraded["B"] <= degraded["C"]
    )
    deterministic = bool(neither_adds)

    branches = [
        ("KEEP CREW AS DEFAULT", keep,
         f"H1 {grades['H1']['holds']}, UCC C>=B on {len(ucc_c_ge_b)}/9 (needs 5), "
         f"H6 {grades['H6']['holds']}"),
        ("HYBRID (deterministic -> single LLM -> crew on multi-domain trigger)", hybrid,
         f"UCC C>B on {len(ucc_c_gt_b)} case(s), {len(hybrid_cases)} of them carrying "
         "the >=2-domain-specialist trigger (needs 3)"),
        ("SINGLE LLM DEFAULT", single,
         f"H5 {grades['H5']['holds']}, UCC B>C on {len(ucc_b_gt_c)} vs C>B on "
         f"{len(ucc_c_gt_b)}, H6 {grades['H6']['holds']}, degraded B "
         f"{degraded['B']} <= C {degraded['C']}"),
        ("DETERMINISTIC DEFAULT + OPTIONAL LLM", deterministic,
         (f"cases where a model arm adds a specific link, a UCC or a discrimination "
          f"over arm A: B {len(adds['B'])}, C {len(adds['C'])} (a majority is "
          f"{majority})") if have_baseline
         else "UNAVAILABLE: arm A's scores are the reference this branch is read "
              "against, and they were not supplied"),
    ]
    if not comparable:
        branches = [
            (name, False,
             "UNAVAILABLE: section 5 compares arms B and C, and "
             f"{sorted({'B', 'C'} - set(by_arm))} did not run")
            for name, _holds, _why in branches
        ]
    selected = [name for name, holds, _why in branches if holds]
    return {
        "read_only_after_grading": True,
        "comparable": comparable,
        "arms_present": sorted(by_arm),
        "cases": len(keys),
        "ucc_per_case": {arm: dict(values) for arm, values in ucc.items()},
        "ucc_C_ge_B_cases": ucc_c_ge_b,
        "ucc_C_gt_B_cases": ucc_c_gt_b,
        "ucc_B_gt_C_cases": ucc_b_gt_c,
        "multi_domain_trigger": triggers,
        "adds_over_arm_A": adds if have_baseline else "UNAVAILABLE (no arm A scores)",
        "majority_needed": majority,
        "degraded_rows": degraded,
        "branches": [
            {"outcome": name, "selected": holds, "numbers": why}
            for name, holds, why in branches
        ],
        "selected": selected,
        "simplify_or_remove_crew": {
            "added": crew_adds_nothing,
            "rule": (
                "added to any outcome in which C's specialists contribute no claim, "
                "link or discrimination that A alone did not, on every case"
            ),
            "cases_where_C_adds_something": adds["C"] if have_baseline else None,
        },
        "outcome": (
            "UNAVAILABLE (arms B and C have not both run)" if not comparable
            else (" + ".join(selected) if selected else "NO BRANCH SELECTED")
            + (" + SIMPLIFY / REMOVE CREW" if crew_adds_nothing else "")
        ),
    }


def cmd_grade(args: argparse.Namespace) -> int:
    payload_manifest, _entries, digest = manifest_script.read_manifest(args.manifest_dir)
    by_arm: dict[str, dict[str, dict[str, Any]]] = {}
    sources: dict[str, str] = {}
    for letter in ("A", "B", "C"):
        path = args.out_dir / f"scores_{letter}.json"
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        by_arm[letter] = _by_case(payload)
        sources[letter] = rel(path)
    missing = [letter for letter in ("A", "B", "C") if letter not in by_arm]
    if missing and not args.partial:
        raise SystemExit(
            f"no scores for arm(s) {missing}. The pre-registered hypotheses compare "
            "arms; grading a comparison one arm has not run would be a number, not a "
            "result. Pass --partial to write what is gradable and say what is not."
        )

    grades = grade_hypotheses(by_arm)
    ucc = recompute_ucc(by_arm)
    triggers = {
        f"{c['corpus']}/{c['case_id']}": int(
            (c.get("necessity_audit") or {}).get("first_step_domain_specialists", 0)
        ) >= 2
        for c in payload_manifest["cases"]
    }
    decision = decision_rule(by_arm, grades, ucc, triggers)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": m19._head(),
        "harness": "scripts/m19b_ablation.py",
        "manifest_hash": digest,
        "sources": sources,
        "arms_graded": sorted(by_arm),
        "arms_missing": missing,
        "constants": {
            "SPECIFIC_MAX_FRACTION": SPECIFIC_MAX_FRACTION,
            "SPECIFIC_MAX_IDS": SPECIFIC_MAX_IDS,
            "TOOL_OUTPUT_BUDGET": TOOL_OUTPUT_BUDGET,
        },
        "grader_reads": (
            "counts, ratios, durations and cited-id sets. No model's prose is read by "
            "any rule in this file."
        ),
        "hypotheses": grades,
        "decision_rule": decision,
    }
    write_artifact(guarded(args.out_dir / GRADING_JSON.name), payload)
    write_text(guarded(args.out_dir / GRADING_MD.name), render_grading(payload))
    print(f"wrote {args.out_dir / GRADING_JSON.name}")
    print(f"wrote {args.out_dir / GRADING_MD.name}")
    for name, block in grades.items():
        print(f"  {name}: holds={block['holds']} (predicted {block['prediction']})")
    print(f"decision rule selects: {decision['outcome']}")
    for branch in decision["branches"]:
        print(f"  [{'x' if branch['selected'] else ' '}] {branch['outcome']}: {branch['numbers']}")
    return 0


def recompute_ucc(by_arm: dict[str, dict[str, dict[str, Any]]]) -> dict[str, dict[str, int]]:
    """UCC per arm per case, recomputed across the arms that actually ran.

    ``score`` records each arm's contributions against itself alone, which cannot decide
    uniqueness. Here the three arms are in hand, so a contribution is unique when its
    signature -- the cited-id set and the domain pair, never the wording -- appears in
    one arm's entries and no other's.
    """
    signatures: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for arm, rows in by_arm.items():
        for key, row in rows.items():
            for entry in row.get("ucc_entries", ()):
                signatures[key][str(entry["signature"])].add(arm)
    counts: dict[str, dict[str, int]] = {arm: {} for arm in by_arm}
    for arm, rows in by_arm.items():
        for key, row in rows.items():
            counts[arm][key] = sum(
                1 for entry in row.get("ucc_entries", ())
                if signatures[key][str(entry["signature"])] == {arm}
            )
    return counts


def render_grading(payload: dict[str, Any]) -> str:
    grades = payload["hypotheses"]
    decision = payload["decision_rule"]
    lines = [
        "# M19b: the pre-registered hypotheses, graded",
        "",
        f"Manifest `{str(payload['manifest_hash'])[:12]}`; arms graded "
        f"{payload['arms_graded']}"
        + (f"; **missing {payload['arms_missing']}**" if payload["arms_missing"] else "")
        + ".",
        "",
        f"> {payload['grader_reads']}",
        "",
        "## H1-H6",
        "",
        link_report.table(
            ["#", "hypothesis", "rule", "predicted", "holds"],
            [
                [name, block["statement"], block["rule"], block["prediction"],
                 str(block["holds"]).upper()]
                for name, block in grades.items()
            ],
        ),
        "",
        "## The decision rule (section 5)",
        "",
        link_report.table(
            ["branch", "selected", "the numbers"],
            [[b["outcome"], "YES" if b["selected"] else "no", b["numbers"]]
             for b in decision["branches"]],
        ),
        "",
        f"**Outcome: {decision['outcome']}**",
        "",
        f"* UCC per case, C >= B on {len(decision['ucc_C_ge_B_cases'])} case(s), "
        f"C > B on {len(decision['ucc_C_gt_B_cases'])}, B > C on "
        f"{len(decision['ucc_B_gt_C_cases'])}",
        f"* cases where a model arm adds a specific link, a UCC or a "
        f"discrimination over arm A: {decision['adds_over_arm_A']}",
        f"* degraded rows: {decision['degraded_rows']}",
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--manifest-dir", type=Path, default=OUT_DIR)
        command.add_argument("--out-dir", type=Path, default=ABLATION_DIR)
        command.add_argument("--substrings", type=Path, default=RUBRIC_SUBSTRINGS_PATH)

    p_sub = sub.add_parser(
        "substrings", help="derive the conclusion substrings from the rubric text",
    )
    p_sub.add_argument("--manifest-dir", type=Path, default=OUT_DIR)
    p_sub.add_argument("--out", type=Path, default=RUBRIC_SUBSTRINGS_PATH)
    p_sub.set_defaults(handler=cmd_substrings)

    p_freeze = sub.add_parser("freeze", help="write the M19b ablation environment")
    p_freeze.add_argument("--manifest-dir", type=Path, default=OUT_DIR)
    p_freeze.add_argument("--out-dir", type=Path, default=ABLATION_DIR)
    p_freeze.set_defaults(handler=cmd_freeze)

    p_run = sub.add_parser("run", help="run one arm over the frozen manifest")
    common(p_run)
    p_run.add_argument("--arm", required=True)
    p_run.add_argument("--repeat", type=int, default=1)
    p_run.add_argument("--check-planner", action="store_true")
    p_run.add_argument("--external", type=Path, default=DEFAULT_EXTERNAL)
    p_run.set_defaults(handler=cmd_run)

    p_score = sub.add_parser("score", help="score one arm's committed rows")
    common(p_score)
    p_score.add_argument("--arm", required=True)
    p_score.add_argument("--rows", type=Path, default=None)
    p_score.add_argument("--arm-a", type=Path, default=None)
    p_score.add_argument("--external", type=Path, default=DEFAULT_EXTERNAL)
    p_score.add_argument("--no-oracle-cache", action="store_true")
    p_score.set_defaults(handler=cmd_score)

    p_grade = sub.add_parser("grade", help="grade H1-H6 and the section 5 decision rule")
    p_grade.add_argument("--manifest-dir", type=Path, default=OUT_DIR)
    p_grade.add_argument("--out-dir", type=Path, default=ABLATION_DIR)
    p_grade.add_argument("--partial", action="store_true")
    p_grade.set_defaults(handler=cmd_grade)

    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
