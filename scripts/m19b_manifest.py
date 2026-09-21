"""M19b T5: the frozen benchmark manifest, its per-case necessity audit, and arm A.

What this script freezes, and why a second manifest exists at all
------------------------------------------------------------------
M19 pinned 22 cases and measured a crew against a single investigator on them. The
answer was unreadable, and ``reports/m19b/necessity/AUDIT.md`` says why in one number:
on 21 of those 22 cases exactly one *domain* specialist was ever eligible, so the
planner was consulted once in the whole experiment. An ablation between a crew and one
agent cannot speak about crews on a case where the crew is one agent wearing four name
tags.

So M19b needs a case set where at least two domain specialists genuinely matter.
``docs/m19b-plan.md`` fixed the test before any case was looked at, T4 ran it over every
corpus this repository can build, and the architect fixed the resulting nine cases
before anything here was measured. This script pins them the way
``scripts/m19_ablation.py`` pins M19's -- corpus, case id, leading rule, member finding
ids, every evidence id, a content hash of the telemetry -- and adds what M19's manifest
had no reason to carry:

* the **necessity audit entry** for the case, from ``ath.evaluation.necessity``: which
  domains have materially relevant evidence, how many domain specialists are eligible at
  step 0 (the number that decides whether the planner is ever asked), how many
  independent evidence sources the case rests on, and whether it qualifies;
* **condition 3** -- what cross-domain synthesis could change -- in one concrete
  sentence per case, copied verbatim from the case's own ``CASE.md`` where it has one;
* the **pre-registered CDER links**: pairs of evidence ids from two domains that ground
  truth says belong to one stage transition, resolved to ATH event ids through
  ``ath.evaluation.external_labels``, so a later task can measure which of them an arm
  recovered rather than arguing about it;
* an **analyst rubric**: the stages, the labelled verdict, and the next action an
  analyst would take if the cross-domain story is true -- written now, before any model
  has seen the case, because a "next action" written afterwards grades the answer
  against itself.

Where the answer key may be read
---------------------------------
Every label-derived field on this page comes from a label file read by
``ath.evaluation`` -- ``load_external_labels`` / ``resolve_refs`` for the injected cases,
``load_ground_truth`` for INC-001. No adapter, rule, triage path, specialist or tool ever
sees one: the telemetry handed to ``run_arm`` is loaded from the same directories with
the same adapters as any other corpus, and nothing in it marks a row as labelled.

``HELDOUT_H1`` is excluded and its sealed answer key is never opened -- not by this
script and not by its tests, which assert it as a runtime path audit rather than as an
intention.

Usage::

    python scripts/m19b_manifest.py build
    python scripts/m19b_manifest.py run          # arm A only, twice, asserted identical

``data/external/`` is gitignored and lives only in the primary checkout, so both
commands take ``--external`` and default to the sibling checkout's copy -- the same
default ``scripts/m19b_necessity_audit.py`` uses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import defaultdict
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import m19_ablation as m19  # noqa: E402
import m19b_link_measure as link_measure  # noqa: E402
import m19b_link_report as link_report  # noqa: E402
import m19b_necessity_audit as necessity_script  # noqa: E402
from ath.correlation.chain import InvestigationCase  # noqa: E402
from ath.evaluation.ablation import (  # noqa: E402
    ARM_BUILDERS,
    CaseManifest,
    CaseResult,
    build_manifest,
    identical,
    load_manifest,
    manifest_hash,
    run_arm,
    telemetry_hash,
    telemetry_rows,
)
from ath.evaluation.ablation.arms import cap_serialised_ids  # noqa: E402
from ath.evaluation.external_labels import (  # noqa: E402
    RESOLVED,
    load_external_labels,
    resolve_labels,
    resolve_refs,
)
from ath.evaluation.necessity import (  # noqa: E402
    TABLE_DOMAIN,
    CaseAudit,
    audit_case,
    event_id_index,
)
from ath.telemetry.loader import Telemetry, load_ground_truth  # noqa: E402

OUT_DIR = ROOT / "reports" / "m19b"
MANIFEST_PATH = OUT_DIR / "MANIFEST.json"
MANIFEST_MD = OUT_DIR / "MANIFEST.md"
ABLATION_DIR = OUT_DIR / "ablation"
CASE_ROOT = OUT_DIR / "cases" / "dedale_injected"
DATA_RAW = ROOT / "data" / "raw"
M19_ARM_A = ROOT / "reports" / "m19" / "ablation" / "arm_A.json"

DEFAULT_EXTERNAL = necessity_script.DEFAULT_EXTERNAL
"""The sibling checkout's ``data/external``. Taken from the audit script rather than
restated, so the two cannot disagree about where the corpora are."""

SEALED_DIRECTORY = "HELDOUT_H1"
"""The held-out case. Named here only so nothing else in this file can name it by
accident; no code path below reads anything under it. ``tests/test_m19b_manifest.py``
audits the filesystem calls a build makes and fails if this directory appears."""


# --------------------------------------------------------------------------------------
# The case set, fixed by the architect before anything was measured
# --------------------------------------------------------------------------------------

INJECTED_CASE_IDS: tuple[str, ...] = ("M1", "M2", "M3", "M4", "L1", "L2")
"""Every unsealed case in ``reports/m19b/cases/dedale_injected/``, in generation order."""

PROVENANCE_SYNTHETIC = "synthetic"
PROVENANCE_INJECTED = "real benign DEDALE background + injected attack rows (labelled)"
PROVENANCE_REAL = "real unlabelled"


@dataclass(frozen=True)
class FlawsPin:
    """One flaws.cloud case, pinned by what does not move when the correlator does.

    A case *number* is assigned by ``ath.correlation.correlator`` in the order connected
    components come out, so it shifts the moment a link changes -- and the link changing
    is exactly what created these two cases (``reports/m19b/link/BEFORE_AFTER.md``).
    The member finding ids are derived from the rule and its first evidence row, and the
    principal is the string the adapters wrote; neither moves unless the corpus does.
    """

    principal: str
    finding_ids: tuple[str, ...]
    case_id_at_pinning: str
    note: str


FLAWS_PINS: tuple[FlawsPin, ...] = (
    FlawsPin(
        principal="backup",
        finding_ids=(
            "ATH-005:cloudtrail-logon-068736",
            "AWS-004:cloudtrail-control-1738515",
        ),
        case_id_at_pinning="CASE-182",
        note=(
            "the first identity x control_plane case the M19b link forms on real "
            "CloudTrail: a failed-logon burst and an authorization-denial burst by the "
            "principal `backup`, spanning 1009s from 2020-04-11T12:40:01Z"
        ),
    ),
    FlawsPin(
        principal="Level6",
        finding_ids=(
            "ATH-005:cloudtrail-logon-078417",
            "AWS-003:cloudtrail-control-1817072",
            "AWS-003:cloudtrail-control-1817745",
            "AWS-003:cloudtrail-control-1818026",
            "AWS-004:cloudtrail-control-1817217",
            "AWS-004:cloudtrail-control-1817767",
            "AWS-004:cloudtrail-control-1818026",
        ),
        case_id_at_pinning="CASE-256",
        note=(
            "the second: seven findings naming the principal `Level6` -- a failed-logon "
            "burst, three service-discovery bursts and three denial bursts -- spanning "
            "2017s from 2020-09-21T03:54:58Z"
        ),
    ),
)
"""Taken from a fresh load at freeze time and re-derived on every build.

``reports/m19b/link/BEFORE_AFTER.md`` names these two cases by number; the numbers are
recorded in ``case_id_at_pinning`` and never used to find the case, because a connected
component's index moves whenever a link does.
"""

SELECTION_RULE = (
    "The M19b benchmark case set was fixed by the architect in the T5 task statement "
    "before anything in this milestone was measured, and this script may not add or "
    "remove a case. It is: "
    "(1) `synthetic:INC-001` -- the single case "
    "`ath.evaluation.incidents.run_incident` investigates for incident INC-001 (the "
    "case with the most malicious overlap), pinned exactly as "
    "`scripts/m19_ablation.py build` pins it; the only one of M19's 22 cases that "
    "qualifies under `docs/m19b-plan.md`'s necessity test "
    "(`reports/m19b/necessity/AUDIT.md`). "
    "(2) `dedale_injected:{M1,M2,M3,M4,L1,L2}` -- every unsealed case in "
    "`reports/m19b/cases/dedale_injected/`, each loaded from its own `winlogbeat/` "
    "directory with `WinlogbeatSource` and hunted, triaged and correlated exactly as "
    "`scripts/m19_ablation.py` does; the single case each forms. `HELDOUT_H1` is "
    "excluded: it is held until the final evaluation and its answer key is sealed. "
    "(3) `flaws_cloud` -- the two identity x control_plane cases the M19b correlation "
    "link forms on real, unlabelled CloudTrail (`reports/m19b/link/BEFORE_AFTER.md`), "
    "pinned by principal and member finding ids rather than by case number, which "
    "shifts when the correlator changes. flaws.cloud is loaded exactly as "
    "`scripts/m19_ablation.py` loads it. "
    "`fixture:cloudtrail`'s new cross-domain case is deliberately excluded: it is a "
    "shipped test fixture, and a benchmark that grades a system on its own fixtures is "
    "grading its own homework."
)

CASE_SET_FROZEN_BY = (
    "docs/m19b-plan.md phase 5-6 (T5), case set named by the architect in the T5 task "
    "statement; no case may be added, removed or adjusted after any measurement"
)


# --------------------------------------------------------------------------------------
# Condition 3, one concrete sentence per case
# --------------------------------------------------------------------------------------

CONDITION_3: dict[str, str] = {
    # Copied verbatim from each case's CASE.md. tests/test_m19b_manifest.py asserts each
    # of these strings still appears in the file it was copied from, so the manifest and
    # the case page cannot drift into two different claims about the same case.
    "dedale_injected:M1": (
        "**Verdict**: an anonymous SYSTEM shell becomes a shell whose arrival is "
        "explained by a credential that was being guessed ninety seconds earlier from a "
        "named host."
    ),
    "dedale_injected:M2": (
        "The identity rows supply the *interval* -- \"a credential for this host was "
        "guessed twelve minutes before this service started\" is a statement neither "
        "domain can make alone, and it is the statement that decides whether the shell "
        "is an admin tool or the second stage of an intrusion."
    ),
    "dedale_injected:M3": (
        "The endpoint rows on CLIENT9 are what turn \"unusual origin\" into \"unusual "
        "origin, then a shell\"."
    ),
    "dedale_injected:M4": (
        "Together they say something neither says: the operator reached execution on "
        "CLIENT3 without a logon this telemetry can show, so **the credential did not "
        "come from this burst**."
    ),
    "dedale_injected:L1": (
        "Only the combination de-escalates, and the next action it produces -- close "
        "it, and ask why an old password was still cached at CLIENT7 -- is not "
        "reachable from either domain alone."
    ),
    "dedale_injected:L2": (
        "Endpoint alone is a MEDIUM finding an analyst sets aside without ever learning "
        "that a dozen failed logons preceded it, and so without asking the one question "
        "that matters -- **is anything else on this estate still authenticating with "
        "the old password?**"
    ),
    # Derived from data/raw/ground_truth.json's stages: the identity stage 7-brute-force
    # sits between two endpoint/network stages, and the transition it explains
    # (8-lateral-movement) is the one this case's CDER links pre-register.
    "synthetic:INC-001": (
        "Ground truth stages 6-credential-access (LSASS dumped on PC01, endpoint), "
        "7-brute-force (fifteen failed network logons for one account from one source, "
        "identity) and 8-lateral-movement (a service-launched shell redirected to an "
        "admin share, endpoint) are three domains' views of one transition: the "
        "endpoint rows alone cannot say the credential the shell used was guessed "
        "rather than known, the identity rows alone cannot say the guessing reached "
        "execution, and only together do they make the archive staged in stage "
        "9-collection the property of an operator who already holds a working "
        "credential -- which is the difference between 'reset an account' and 'isolate "
        "two hosts'."
    ),
    # Written from the findings themselves; flaws.cloud ships no labels, so nothing here
    # is a claim about what happened.
    "flaws_cloud:backup": (
        "Apart, each finding has a dull reading and gets a routine answer: a burst of "
        "failed logons for `backup` that never succeeds is someone mistyping a "
        "password, and an authorization-denial burst by `backup` minutes later is a "
        "script with a stale policy. Together -- one principal failing to authenticate "
        "and then being refused across the control plane inside one 1009-second window "
        "-- they read as a caller probing what a credential can reach, which makes the "
        "next question whose hands are on that credential rather than a password reset "
        "and a policy fix filed separately."
    ),
    "flaws_cloud:Level6": (
        "Apart, the identity burst is a login problem and the six control-plane "
        "findings are a permissions problem, and on a deliberately vulnerable public "
        "account both are closed unread. Together they say the principal whose "
        "authentication is failing is the same principal enumerating services and "
        "collecting refusals across the same 2017-second window, so the question stops "
        "being \"why was this call denied\" and becomes \"whose hands are on this "
        "credential\" -- which changes the priority and who is asked, on evidence the "
        "corpus always carried and the correlator could not read until M19b."
    ),
}

NEXT_ACTION: dict[str, str] = {
    # One sentence per case, written before any arm ran: what an analyst would do next
    # if the cross-domain story the case tells is true.
    "synthetic:INC-001": (
        "Isolate PC01 and the file server the svc_backup logons reached, reset "
        "svc_backup and jdoe, and block 185.220.101.47 at the perimeter -- the LSASS "
        "dump plus the guessed credential plus the staged archive is a live operator "
        "with a working credential, not three separate alerts."
    ),
    "dedale_injected:M1": (
        "Contain CLIENT7 before CLIENT9: it is the operator's foothold, it appears only "
        "in the identity rows, and resetting client9's password without it leaves "
        "whoever guessed the password free to guess the next one."
    ),
    "dedale_injected:M2": (
        "Reset client3's credential and then sweep the twelve minutes between the "
        "successful logon and the service-launched shell for anything else that "
        "credential touched, because at this spacing what else it reached is the open "
        "question and not what it did on the target."
    ),
    "dedale_injected:M3": (
        "Ask why CLIENT7 is authenticating as an account that has no session on it, and "
        "treat the CLIENT9 shell as the answer that turns an unusual origin into a "
        "confirmed foothold worth containing."
    ),
    "dedale_injected:M4": (
        "Widen collection rather than contain: execution reached CLIENT3 without a "
        "successful logon this telemetry can show, so the next action is to find the "
        "authentication that is missing -- a host already compromised, or a logon path "
        "this collection does not cover."
    ),
    "dedale_injected:L1": (
        "Close it as a service-desk action and ask why CLIENT7 still held client9's old "
        "password, because a lockout cascade, an account that owns the target host and "
        "a spooler restart are a ticket rather than an intrusion."
    ),
    "dedale_injected:L2": (
        "Close it as an operational finding, fix the stored credential on the nightly "
        "backup job, and check whether anything else on the estate is still "
        "authenticating with the old password."
    ),
    "flaws_cloud:backup": (
        "If the two findings are one actor, rotate the `backup` principal's credentials "
        "and review every management call it made in the window; if they are not, the "
        "denials are a policy bug and the logins are a person, and the case should be "
        "split rather than escalated."
    ),
    "flaws_cloud:Level6": (
        "If the two findings are one actor, rotate `Level6`'s credentials and review "
        "what it reached on the control plane during the 34 minutes the case spans, "
        "starting with the calls that were allowed rather than the ones that were "
        "refused."
    ),
}


# --------------------------------------------------------------------------------------
# Loading: the M19 loaders, pointed at the external checkout
# --------------------------------------------------------------------------------------


@contextmanager
def external_root(external: Path) -> Iterator[None]:
    """Point the M19 cloud loader at the checkout that actually has ``data/external``.

    ``scripts/m18_cloud_detection.load_corpus`` -- which ``scripts/m19_ablation.py``
    calls for flaws.cloud -- resolves its path from that module's ``ROOT`` at call time.
    This worktree has no ``data/external`` (it is gitignored and exists in the primary
    checkout), so the root is rebound for the duration of the load instead of the corpus
    being re-loaded here by a second, parallel copy of the same three lines. The point of
    "exactly as scripts/m19_ablation.py loads it" is that it is the *same call*.
    """
    import m18_cloud_detection as m18  # noqa: PLC0415

    expected = external.parent.parent / "data" / "external"
    if expected.resolve() != external.resolve():
        raise SystemExit(
            f"--external must be a path ending in data/external (got {external}); "
            "the M19 loader builds its own path from a checkout root, and rebinding "
            "that root is only meaningful when the two agree."
        )
    original = m18.ROOT
    m18.ROOT = external.parent.parent
    try:
        yield
    finally:
        m18.ROOT = original


def synthetic_bundle() -> m19.Bundle:
    """INC-001's bundle, from ``scripts/m19_ablation.py``'s own suite loader."""
    for bundle in m19.load_bundles(["synthetic"]):
        if bundle.name == "synthetic:INC-001":
            return bundle
    raise SystemExit("the standard suite produced no synthetic:INC-001 bundle")


def injected_bundle(case_id: str) -> m19.Bundle:
    """One injected case directory, loaded and put through the M19 pipeline.

    Each case is its own corpus because each carries its own telemetry and therefore its
    own hash -- the same reason ``synthetic:INC-00n`` is a corpus per incident.
    """
    if case_id not in INJECTED_CASE_IDS:
        raise SystemExit(f"{case_id!r} is not one of the benchmark's injected cases")
    started = time.perf_counter()
    telemetry = necessity_script._winlogbeat(CASE_ROOT / case_id / "winlogbeat")
    load_seconds = time.perf_counter() - started
    started = time.perf_counter()
    findings, cases, environment, assessments = m19._pipeline(telemetry)
    return m19.Bundle(
        name=f"dedale_injected:{case_id}",
        telemetry=telemetry, findings=findings, cases=cases, environment=environment,
        assessments=assessments, load_seconds=load_seconds,
        pipeline_seconds=time.perf_counter() - started,
    )


def flaws_bundle(external: Path) -> m19.Bundle:
    """flaws.cloud, through ``scripts/m19_ablation.py``'s loader and pipeline."""
    started = time.perf_counter()
    with external_root(external):
        telemetry = m19._load_telemetry("flaws_cloud")
    load_seconds = time.perf_counter() - started
    started = time.perf_counter()
    findings, cases, environment, assessments = m19._pipeline(telemetry)
    return m19.Bundle(
        name="flaws_cloud",
        telemetry=telemetry, findings=findings, cases=cases, environment=environment,
        assessments=assessments, load_seconds=load_seconds,
        pipeline_seconds=time.perf_counter() - started,
    )


def bundles(external: Path) -> Iterator[m19.Bundle]:
    """Every corpus the benchmark needs, cheapest first.

    flaws.cloud is last on purpose: it is 1.9M rows and several minutes, and a mistake in
    one of the eight cheap cases should surface before it is paid for.
    """
    yield synthetic_bundle()
    for case_id in INJECTED_CASE_IDS:
        yield injected_bundle(case_id)
    yield flaws_bundle(external)


def select_case(bundle: m19.Bundle) -> tuple[InvestigationCase, ...]:
    """Which of a corpus's cases the frozen set names, and nothing else."""
    if bundle.name == "synthetic:INC-001":
        selected, _selection, _detail = m19.select(bundle)
        return tuple(selected)
    if bundle.name.startswith("dedale_injected:"):
        if len(bundle.cases) != 1:
            raise SystemExit(
                f"{bundle.name}: expected exactly one correlated case, got "
                f"{len(bundle.cases)}. The case set is frozen; a directory that now "
                "forms a different number of cases is a changed benchmark, not a new "
                "measurement."
            )
        return (bundle.cases[0],)
    if bundle.name == "flaws_cloud":
        return tuple(case for _pin, case in resolve_flaws_pins(bundle))
    raise SystemExit(f"no selection rule for corpus {bundle.name!r}")


def resolve_flaws_pins(
    bundle: m19.Bundle,
) -> list[tuple[FlawsPin, InvestigationCase]]:
    """Find each pinned flaws.cloud case by its member finding ids, and check the rest.

    The finding ids are the identity; the case number and the principal are checked
    against the pin and reported, never used to find the case. A pin that matches no case
    or more than one is a refusal: on an unlabelled corpus of 279 cases, quietly
    investigating a different one is the failure mode with no symptom.
    """
    by_findings = {
        tuple(sorted(f.finding_id for f in case.findings)): case for case in bundle.cases
    }
    resolved: list[tuple[FlawsPin, InvestigationCase]] = []
    for pin in FLAWS_PINS:
        case = by_findings.get(tuple(sorted(pin.finding_ids)))
        if case is None:
            raise SystemExit(
                f"flaws_cloud: no case is made of exactly {list(pin.finding_ids)} "
                f"(pinned as {pin.case_id_at_pinning}, principal {pin.principal!r}). "
                f"The corpus produced {len(bundle.cases)} case(s); refusing to "
                "substitute another."
            )
        principals = case_principals(bundle.telemetry, case)
        if pin.principal not in principals:
            raise SystemExit(
                f"flaws_cloud/{case.case_id}: the pinned principal {pin.principal!r} is "
                f"not named by this case's rows ({principals}); the finding ids match a "
                "case the pin does not describe."
            )
        resolved.append((pin, case))
    return resolved


def case_principals(telemetry: Telemetry, case: InvestigationCase) -> list[str]:
    """Principals this case's rows name, through the link report's own reader."""
    cited = {str(e) for e in case.event_ids}
    by_event = link_measure.principals_by_event(telemetry, cited)
    return sorted({p for event in cited for p in by_event.get(event, ())})


# --------------------------------------------------------------------------------------
# The answer keys: read here, never by anything the arms touch
# --------------------------------------------------------------------------------------


def injected_labels(case_id: str) -> dict[str, Any]:
    """The raw label payload for one injected case.

    Read directly for the ``links`` block, which ``ExternalLabels`` does not model --
    it is a benchmark artifact of this milestone rather than part of the label format --
    and through ``load_external_labels`` for everything the format does model, so the
    provenance and the malicious flag are validated by the same code every other
    consumer uses.
    """
    path = CASE_ROOT / case_id / "labels.json"
    return json.loads(path.read_text(encoding="utf-8"))


def injected_links(
    case_id: str, telemetry: Telemetry, payload: dict[str, Any],
) -> list[dict[str, Any]]:
    """The case's pre-registered links, native refs resolved to ATH event ids."""
    refs = [
        side["ref"]
        for entry in payload.get("links", ())
        for side in (entry["identity"], entry["endpoint"])
    ]
    resolved = resolve_refs(refs, telemetry)
    links: list[dict[str, Any]] = []
    for entry in payload.get("links", ()):
        sides = {}
        for domain in ("identity", "endpoint"):
            ref = entry[domain]["ref"]
            match = resolved[ref]
            if match.status != RESOLVED:
                raise SystemExit(
                    f"{case_id}/{entry['link_id']}: the {domain} ref {ref!r} is "
                    f"{match.status} against this load ({len(match.event_ids)} row(s)). "
                    "A pre-registered link that does not name an ingested row cannot be "
                    "scored, and silently dropping it would shrink the denominator."
                )
            sides[domain] = {
                "domain": domain,
                "ref": ref,
                "event_id": match.event_id,
                "channel": entry[domain].get("channel", ""),
                "record_id": entry[domain].get("record_id"),
            }
        links.append({
            "link_id": entry["link_id"],
            "stage_transition": entry["stage_transition"],
            "note": entry.get("note", ""),
            "source": f"reports/m19b/cases/dedale_injected/{case_id}/labels.json",
            **sides,
        })
    return links


INC001_SOURCE_STAGES: tuple[str, ...] = ("6-credential-access", "7-brute-force")
INC001_TARGET_STAGE = "8-lateral-movement"
INC001_LINK_RULE = (
    "every (source, target) pair of ground-truth event ids where the source is in stage "
    f"{' or '.join(INC001_SOURCE_STAGES)} and the target is in the stage that follows "
    f"them, {INC001_TARGET_STAGE}, kept only when the two ids belong to different "
    "domains. Stage 6's single id is a process row and stage 8's is a process row, so "
    "every surviving pair is identity x endpoint: one of the fifteen failed/successful "
    "network logons paired with the service-launched shell they explain."
)


def domain_of_events(telemetry: Telemetry) -> dict[str, str]:
    """Which domain each ingested event id belongs to, by the table it lives in."""
    index = event_id_index(telemetry)
    return {
        event_id: TABLE_DOMAIN[event_type]
        for event_type, ids in index.items()
        for event_id in ids
    }


def inc001_links(telemetry: Telemetry) -> list[dict[str, Any]]:
    """INC-001's cross-domain stage-transition pairs, from ``ground_truth.json``.

    The synthetic generator hands out ``event_id`` itself, so these ids need no
    resolution -- which is the difference between a corpus this repository generated and
    one it did not, and the reason ``ath.evaluation.external_labels`` exists for the
    others.
    """
    truth = load_ground_truth(DATA_RAW)
    stages = truth["scenarios"]["intrusion"]["stages"]
    domains = domain_of_events(telemetry)
    links: list[dict[str, Any]] = []
    for stage in INC001_SOURCE_STAGES:
        for source in stages[stage]["event_ids"]:
            for target in stages[INC001_TARGET_STAGE]["event_ids"]:
                source_domain = domains.get(source, "")
                target_domain = domains.get(target, "")
                if not source_domain or not target_domain:
                    continue
                if source_domain == target_domain:
                    continue
                if {source_domain, target_domain} != {"identity", "endpoint"}:
                    # Every consumer below -- the manifest's link table, the markdown
                    # renderer and recovered_links -- addresses a link by the names
                    # `identity` and `endpoint`. On this incident's stages that is what
                    # the pairs are; a future stage pairing, say, network with endpoint
                    # would silently produce links no scorer could read, so it stops here
                    # instead.
                    raise SystemExit(
                        f"INC-001: stage transition {stage} -> {INC001_TARGET_STAGE} pairs {source_domain} with {target_domain}, which is "
                        "not the identity x endpoint shape every CDER consumer "
                        "addresses by name. Widen the link schema deliberately rather "
                        "than emitting a link nothing can score."
                    )
                pair = {
                    source_domain: {
                        "domain": source_domain, "ref": "", "event_id": source,
                        "stage": stage, "channel": "", "record_id": None,
                    },
                    target_domain: {
                        "domain": target_domain, "ref": "", "event_id": target,
                        "stage": INC001_TARGET_STAGE, "channel": "", "record_id": None,
                    },
                }
                links.append({
                    "link_id": f"INC-001-LINK-{len(links) + 1:02d}",
                    "stage_transition": f"{stage} -> {INC001_TARGET_STAGE}",
                    "note": (
                        f"{stages[stage]['note']} -> "
                        f"{stages[INC001_TARGET_STAGE]['note']}"
                    ),
                    "source": "data/raw/ground_truth.json",
                    **pair,
                })
    return links


# --------------------------------------------------------------------------------------
# Hashes of the inputs that are not telemetry
# --------------------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def directory_digest(directory: Path) -> tuple[str, dict[str, str]]:
    """A digest over a case directory: every file's relative path and its sha256.

    Order-independent by sorting, path-sensitive by construction -- a file renamed, added
    or removed changes the digest even when the bytes of every other file are unchanged.
    """
    files = {
        str(path.relative_to(directory)).replace("\\", "/"): sha256_file(path)
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(f"{name}:{files[name]}\n".encode())
    return digest.hexdigest(), files


def flaws_tar_digest(external: Path) -> dict[str, Any]:
    """The flaws.cloud tar's published digest, read from ``data/external/MANIFEST.json``.

    Read rather than recomputed: the external manifest is what says which bytes were
    fetched on which day, and recomputing a 252 MB digest on every build would answer a
    question nobody asked while making the build minutes slower.
    """
    path = external / "MANIFEST.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    entry = payload["datasets"]["flaws_cloud"]
    return {
        "source": str(path),
        "url": entry.get("url", ""),
        "fetched_on": entry.get("fetched_on", ""),
        "files": [
            {"path": f["path"], "bytes": f["bytes"], "sha256": f["sha256"]}
            for f in entry.get("files", ())
        ],
    }


# --------------------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------------------


@dataclass
class BenchmarkCase:
    """One pinned case and everything the benchmark records about it."""

    key: str
    corpus: str
    provenance: str
    entry: CaseManifest
    audit: CaseAudit
    condition_3: str
    links: list[dict[str, Any]]
    cder: str
    rubric: dict[str, Any]
    label_source: str
    rule_titles: dict[str, str] = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        audit = self.audit.to_dict()
        return {
            **self.entry.to_dict(),
            "provenance": self.provenance,
            "rule_titles": dict(self.rule_titles),
            "necessity_audit": {
                key: audit[key]
                for key in (
                    "domains", "domains_by_finding", "channels",
                    "first_step_eligible", "first_step_domain_specialists",
                    "whole_run_eligible", "whole_run_specialists_eligible",
                    "agents_run", "evidence_sources", "independent_evidence_sources",
                    "tactics", "techniques",
                    "two_domains", "non_redundant", "synthesis_could_change",
                    "qualifies", "failure_reason", "synthesis_statement",
                )
            },
            "condition_3": self.condition_3,
            "cder": self.cder,
            "links": list(self.links),
            "rubric": dict(self.rubric),
            "label_source": self.label_source,
            "notes": self.notes,
        }


CDER_UNAVAILABLE = "UNAVAILABLE (unlabelled)"
"""What the CDER column says on a corpus with no answer key.

Not zero, and not omitted. A zero would read as "this arm recovered none of the links",
which is a measurement; the honest statement is that the links are undefined, because
flaws.cloud names no event ids in any narrative and never will.
"""


def _rule_titles(case: InvestigationCase) -> dict[str, str]:
    return {f.rule_id: f.title for f in sorted(case.findings, key=lambda f: f.rule_id)}


def build_synthetic_case(bundle: m19.Bundle, case: InvestigationCase) -> BenchmarkCase:
    incident = bundle.incident
    assert incident is not None
    truth = load_ground_truth(DATA_RAW)
    stages = truth["scenarios"]["intrusion"]["stages"]
    ground_truth = {
        "labelled": True,
        "incident_id": incident.incident_id,
        "name": incident.name,
        "malicious_events": len(incident.malicious_event_ids),
        "expected_techniques": sorted(incident.expected_techniques),
        "stages": list(stages),
    }
    entry = build_manifest(
        bundle.name, bundle.telemetry, [case],
        selection="the case run_incident investigates for this incident",
        labels={case.case_id: {
            "incident_id": incident.incident_id,
            "provenance": PROVENANCE_SYNTHETIC,
            "verdict": "malicious",
        }},
    )[0]
    links = inc001_links(bundle.telemetry)
    return BenchmarkCase(
        key="synthetic:INC-001",
        corpus=bundle.name,
        provenance=PROVENANCE_SYNTHETIC,
        entry=entry,
        audit=audit_case(
            case, corpus=bundle.name, provenance=PROVENANCE_SYNTHETIC,
            telemetry=bundle.telemetry, findings=bundle.findings, cases=bundle.cases,
            environment=bundle.environment,
            corpus_channels=bundle.environment.observable_channels,
            ground_truth=ground_truth,
        ),
        condition_3=CONDITION_3["synthetic:INC-001"],
        links=links,
        cder=f"DEFINED ({len(links)} pre-registered link(s))",
        rubric={
            "stages": list(stages),
            "verdict": "malicious",
            "next_action": NEXT_ACTION["synthetic:INC-001"],
            "stages_source": "data/raw/ground_truth.json, scenario `intrusion`",
        },
        label_source=(
            "data/raw/ground_truth.json, via ath.telemetry.loader.load_ground_truth -- "
            "the reader ath.evaluation.suite uses and the only one permitted to"
        ),
        rule_titles=_rule_titles(case),
        notes=(
            "M19 pinned this same case. The M19b correlation link is asserted not to "
            "change its finding set; `build` checks that against "
            "reports/m19/ablation/MANIFEST.json rather than taking it on trust."
        ),
    )


def build_injected_case(
    case_id: str, bundle: m19.Bundle, case: InvestigationCase,
) -> BenchmarkCase:
    payload = injected_labels(case_id)
    labels = load_external_labels(CASE_ROOT / case_id / "labels.json")
    resolved = resolve_labels(labels, bundle.telemetry)
    unresolved = {k: v for k, v in resolved.unresolved.items() if v}
    ambiguous = {k: v for k, v in resolved.ambiguous.items() if v}
    if unresolved or ambiguous:
        raise SystemExit(
            f"dedale_injected:{case_id}: the answer key has holes against this load -- "
            f"unresolved {unresolved}, ambiguous {ambiguous}. Every injected ref must name exactly one "
            "ingested row, or the labels describe a different corpus from the one the "
            "arms will investigate."
        )
    if len(labels.scenarios) != 1:
        raise SystemExit(
            f"dedale_injected:{case_id}: {len(labels.scenarios)} scenarios. Each case in this directory carries "
            "exactly one story, and the rubric's verdict is that story's."
        )
    scenario = labels.scenarios[0]
    stage_notes = {
        stage_name: spec.get("note", "")
        for stage_name, spec in payload["scenarios"][scenario.name]["stages"].items()
    }
    ground_truth = {
        "labelled": True,
        "provenance": labels.provenance,
        "scenario": scenario.name,
        "malicious": scenario.malicious,
        "note": scenario.note,
        "stages": {s.name: {"refs": len(s.refs), "note": s.note} for s in scenario.stages},
        "refs_total": resolved.total_refs,
        "refs_resolved": resolved.resolved_refs,
    }
    entry = build_manifest(
        bundle.name, bundle.telemetry, [case],
        selection=(
            f"the single case reports/m19b/cases/dedale_injected/{case_id}/ forms when its "
            "winlogbeat/ directory is hunted, triaged and correlated"
        ),
        labels={case.case_id: {
            "injected_case": case_id,
            "provenance": labels.provenance,
            "scenario": scenario.name,
            "verdict": "malicious" if scenario.malicious else "benign",
        }},
    )[0]
    links = injected_links(case_id, bundle.telemetry, payload)
    return BenchmarkCase(
        key=f"dedale_injected:{case_id}",
        corpus=bundle.name,
        provenance=PROVENANCE_INJECTED,
        entry=entry,
        audit=audit_case(
            case, corpus=bundle.name, provenance=PROVENANCE_INJECTED,
            telemetry=bundle.telemetry, findings=bundle.findings, cases=bundle.cases,
            environment=bundle.environment,
            corpus_channels=bundle.environment.observable_channels,
            ground_truth=ground_truth,
        ),
        condition_3=CONDITION_3[f"dedale_injected:{case_id}"],
        links=links,
        cder=f"DEFINED ({len(links)} pre-registered link(s))",
        rubric={
            "stages": [s.name for s in scenario.stages],
            "stage_notes": stage_notes,
            "verdict": "malicious" if scenario.malicious else "benign",
            "next_action": NEXT_ACTION[f"dedale_injected:{case_id}"],
            "stages_source": (
                f"reports/m19b/cases/dedale_injected/{case_id}/labels.json, scenario "
                f"`{scenario.name}`"
            ),
        },
        label_source=(
            f"reports/m19b/cases/dedale_injected/{case_id}/labels.json, via "
            "ath.evaluation.external_labels"
        ),
        rule_titles=_rule_titles(case),
        notes=(
            "Real benign DEDALE background with a labelled endpoint x identity chain "
            "injected by scripts/m19b_inject_dedale.py -- not real data about an "
            "intrusion, however real the background is."
        ),
    )


def build_flaws_case(
    pin: FlawsPin, bundle: m19.Bundle, case: InvestigationCase,
    evidence_index: dict[str, set[str]] | None = None,
) -> BenchmarkCase:
    principals = case_principals(bundle.telemetry, case)
    ground_truth = {
        "labelled": False,
        "note": (
            "flaws.cloud ships no attack labels: the published narrative describes CTF "
            "levels, not event ids, so no stage of this case can be confirmed and the "
            "rubric's verdict is `unknown`."
        ),
        "principals": principals,
    }
    entry = build_manifest(
        bundle.name, bundle.telemetry, [case],
        selection=(
            f"{pin.note}; pinned by member finding ids and the principal '{pin.principal}', not by case "
            "number"
        ),
        labels={case.case_id: {
            "provenance": "real",
            "principal": pin.principal,
            "verdict": "unknown",
        }},
    )[0]
    return BenchmarkCase(
        key=f"flaws_cloud:{pin.principal}",
        corpus=bundle.name,
        provenance=PROVENANCE_REAL,
        entry=entry,
        audit=audit_case(
            case, corpus=bundle.name, provenance=PROVENANCE_REAL,
            telemetry=bundle.telemetry, findings=bundle.findings, cases=bundle.cases,
            environment=bundle.environment,
            corpus_channels=bundle.environment.observable_channels,
            ground_truth=ground_truth,
            evidence_index=evidence_index,
        ),
        condition_3=CONDITION_3[f"flaws_cloud:{pin.principal}"],
        links=[],
        cder=CDER_UNAVAILABLE,
        rubric={
            # Distinct rule titles in rule-id order: CASE-256 carries seven findings
            # from three rules, and listing "Authorization-denial burst" three times
            # would describe the rule catalogue rather than the case.
            "stages": list(_rule_titles(case).values()),
            "verdict": "unknown",
            "next_action": NEXT_ACTION[f"flaws_cloud:{pin.principal}"],
            "stages_source": (
                "the member findings' distinct rule titles -- this corpus has no "
                "ground truth, so it has no stages, and saying so is the measurement"
            ),
        },
        label_source="none (unlabelled corpus)",
        rule_titles=_rule_titles(case),
        notes=(
            "Principals named by this case's rows: {}. Pinned as {} at freeze time; the "
            "case number is recorded, never relied on.".format(
                ", ".join(principals), pin.case_id_at_pinning,
            )
        ),
    )


def build_cases(external: Path) -> tuple[list[BenchmarkCase], dict[str, Any]]:
    """Every case in the frozen set, with its corpus's own accounting."""
    built: list[BenchmarkCase] = []
    corpora: dict[str, Any] = {}
    for bundle in bundles(external):
        selected = select_case(bundle)
        if bundle.name == "synthetic:INC-001":
            built.append(build_synthetic_case(bundle, selected[0]))
        elif bundle.name.startswith("dedale_injected:"):
            case_id = bundle.name.split(":", 1)[1]
            built.append(build_injected_case(case_id, bundle, selected[0]))
        else:
            # One index over 1.9M rows for both cases; see necessity.event_id_index.
            index = event_id_index(bundle.telemetry)
            for pin, case in resolve_flaws_pins(bundle):
                built.append(build_flaws_case(pin, bundle, case, evidence_index=index))
        corpora[bundle.name] = {
            "telemetry_hash": telemetry_hash(bundle.telemetry),
            "rows": telemetry_rows(bundle.telemetry),
            "findings": len(bundle.findings),
            "cases_in_corpus": len(bundle.cases),
            "cases_pinned": len(selected),
            "load_seconds": round(bundle.load_seconds, 1),
            "pipeline_seconds": round(bundle.pipeline_seconds, 1),
        }
        print(
            f"{bundle.name}: {len(bundle.findings)} finding(s), {len(bundle.cases)} case(s), {len(selected)} pinned",
            flush=True,
        )
    return built, corpora


def source_hashes(external: Path) -> dict[str, Any]:
    """Content hashes for every input that is not one of the canonical tables.

    The telemetry hash answers "is this the same corpus"; these answer "are these the
    same *files*", which is the question a reader of a committed case directory has.
    """
    injected = json.loads((CASE_ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    directories: dict[str, Any] = {}
    for case_id in INJECTED_CASE_IDS:
        digest, files = directory_digest(CASE_ROOT / case_id)
        published = injected["cases"][case_id]["files"]
        differing = sorted(
            name for name, value in files.items()
            if published.get(name) not in (None, value)
        )
        if differing:
            raise SystemExit(
                f"dedale_injected:{case_id}: {len(differing)} file(s) differ from the digests "
                f"reports/m19b/cases/dedale_injected/MANIFEST.json publishes: {differing}"
            )
        directories[case_id] = {
            "directory": f"reports/m19b/cases/dedale_injected/{case_id}",
            "sha256": digest,
            "files": files,
        }
    return {
        "dedale_injected_case_directories": directories,
        "dedale_injected_manifest_sha256": sha256_file(CASE_ROOT / "MANIFEST.json"),
        "dedale_source_files": injected.get("source_files", {}),
        "dedale_generator": {
            "script": injected.get("script", ""),
            "sha256": injected.get("script_sha256", ""),
            "seed": injected.get("seed"),
        },
        "flaws_cloud": flaws_tar_digest(external),
        "synthetic_ground_truth_sha256": sha256_file(DATA_RAW / "ground_truth.json"),
    }


# --------------------------------------------------------------------------------------
# The rebuild guard
# --------------------------------------------------------------------------------------


def input_differences(
    existing: dict[str, Any], entries: Sequence[CaseManifest],
) -> list[str]:
    """How a rebuild's inputs differ from the frozen manifest's, case by case.

    A manifest exists to say that every arm saw the same thing. Overwriting one because
    the corpus moved would destroy the only record that it moved, and the next arm's
    rows would compare cleanly against a baseline nobody can reproduce -- so a rebuild
    over changed telemetry is refused, not warned about. The differences are returned
    rather than raised so a test can assert the refusal without rebuilding anything.
    """
    previous = {entry.key: entry for entry in load_manifest(existing)}
    current = {entry.key: entry for entry in entries}
    differences: list[str] = []
    for key in sorted(set(previous) & set(current)):
        was, now = previous[key], current[key]
        if was.telemetry_hash != now.telemetry_hash:
            differences.append(
                f"{key}: telemetry hash {was.telemetry_hash[:12]} -> {now.telemetry_hash[:12]}; the corpus this case is investigated "
                "against is not the corpus the manifest pinned"
            )
        if was.finding_ids != now.finding_ids:
            differences.append(
                f"{key}: finding ids {list(was.finding_ids)} -> {list(now.finding_ids)}; a case id is not an identity, its findings "
                "are"
            )
        if was.evidence_ids != now.evidence_ids:
            differences.append(
                f"{key}: {len(was.evidence_ids)} evidence id(s) -> {len(now.evidence_ids)}"
            )
    for key in sorted(set(previous) - set(current)):
        differences.append(f"{key}: pinned in the frozen manifest and absent now")
    for key in sorted(set(current) - set(previous)):
        differences.append(f"{key}: not in the frozen manifest; the case set is fixed")
    return differences


def refuse_if_inputs_moved(path: Path, entries: Sequence[CaseManifest]) -> None:
    if not path.exists():
        return
    differences = input_differences(
        json.loads(path.read_text(encoding="utf-8")), entries,
    )
    if not differences:
        return
    raise SystemExit(
        "refusing to rebuild {}: {} case(s) would be pinned against different "
        "inputs:\n  {}\n\nThe frozen manifest is the only evidence that the arms saw "
        "one corpus. If the corpora genuinely moved, delete the file deliberately and "
        "say in the commit message what moved and why -- a manifest quietly rewritten "
        "under a changed corpus is a comparison table whose rows came from different "
        "experiments.".format(path, len(differences), "\n  ".join(differences))
    )


# --------------------------------------------------------------------------------------
# MANIFEST.md
# --------------------------------------------------------------------------------------


LIMITATIONS = (
    "**Six of the nine cases are constructed.** `dedale_injected:*` is real benign "
    "DEDALE telemetry with a hand-written chain injected into it. The background is "
    "real; the intrusion is not, and no row of this benchmark should be read as "
    "evidence about real attacker behaviour.",
    "**Every constructed case is endpoint x identity**, because that is the only "
    "cross-domain pair `ath.correlation.correlator` can form on Winlogbeat telemetry. "
    "The benchmark therefore measures whether a crew helps on *one* kind of "
    "cross-domain investigation (VERIFIED FROM CODE; the argument is in each CASE.md "
    "and in `reports/m19b/necessity/AUDIT.md`).",
    "**The two real cases carry no ground truth.** flaws.cloud names no event ids in "
    "any published narrative, so their verdict is `unknown`, their CDER is "
    "`" + CDER_UNAVAILABLE + "`, and nothing here claims they are intrusions. They are "
    "in the set because they are the only *real* cases in this repository on which two "
    "domain specialists have materially relevant evidence.",
    "**INC-001's links are mechanical.** The plan defines a link as a pair of evidence "
    "ids two domains contribute to one stage transition; ground truth gives stage "
    "membership and not a representative row, so " + INC001_LINK_RULE.split(".")[0] +
    " -- which makes the denominator fifteen near-identical links rather than one. A "
    "CDER of 1/15 on this case means the same thing as 1/1 would; the ratio is "
    "comparable between arms and not between cases.",
    "**A rubric's next action is one analyst's judgement**, written before any run and "
    "committed so it cannot be revised afterwards. It is a pre-registration, not a "
    "ground truth, and a later task may not promote it to one.",
    "**The held-out case `HELDOUT_H1` is not here**, and its answer key is sealed. "
    "Nothing in this manifest, this script, or its tests opens it.",
)


def render_markdown(payload: dict[str, Any]) -> str:
    """``MANIFEST.md``: the same content as the JSON, in the order a reader needs it."""
    cases = payload["cases"]
    out: list[str] = []
    out.append("# M19b: the frozen benchmark manifest\n")
    out.append(
        "Generated {} at `{}`. Manifest hash `{}`; benchmark hash `{}` (the manifest "
        "hash covers the pinned inputs `run_arm` checks -- corpus, case, findings, "
        "evidence, telemetry; the benchmark hash covers those *and* every audit, link "
        "and rubric on this page).\n".format(
            payload["generated_at"], payload["head"],
            payload["manifest_hash"], payload["benchmark_hash"],
        )
    )
    out.append(
        "Every number below is MEASURED: each corpus was loaded through the pipeline's "
        "own adapters, hunted, triaged and correlated exactly as "
        "`scripts/m19_ablation.py` does, and each case's necessity entry was produced "
        "by `ath.evaluation.necessity.audit_case`, which runs arm A's deterministic "
        "investigation rather than predicting it. No model was called. Every "
        "label-derived field was read by `ath.evaluation`; no adapter, rule, triage "
        "path, specialist or tool saw one.\n"
    )

    out.append("## The selection rule\n")
    out.append("Frozen by: " + payload["case_set_frozen_by"] + "\n")
    out.append(payload["selection_rule"] + "\n")
    out.append("Excluded, and why:\n")
    out.append(link_report.table(
        ["excluded", "reason"],
        [[e["what"], e["reason"]] for e in payload["excluded"]],
    ) + "\n")

    out.append("## The nine cases\n")
    out.append(link_report.table(
        ["case", "corpus", "provenance", "leading rule", "rules", "findings",
         "evidence ids", "domains", "domain specialists at step 0",
         "independent evidence sources", "qualifies", "CDER links", "verdict"],
        [
            [
                "`{}`".format(case["case_id"]),
                "`{}`".format(case["corpus"]),
                case["provenance"],
                case["leading_rule"],
                ", ".join(case["rule_ids"]),
                len(case["finding_ids"]),
                len(case["evidence_ids"]),
                ", ".join(case["necessity_audit"]["domains"]),
                case["necessity_audit"]["first_step_domain_specialists"],
                case["necessity_audit"]["independent_evidence_sources"],
                "YES" if case["necessity_audit"]["qualifies"] else "no",
                len(case["links"]) if case["links"] else case["cder"],
                case["rubric"]["verdict"],
            ]
            for case in cases
        ],
    ) + "\n")

    out.append("## Corpora\n")
    out.append(link_report.table(
        ["corpus", "process", "network", "logon", "control", "findings",
         "cases in corpus", "cases pinned", "telemetry hash", "load s", "pipeline s"],
        [
            [
                f"`{name}`",
                corpus["rows"]["process"], corpus["rows"]["network"],
                corpus["rows"]["logon"], corpus["rows"]["control"],
                corpus["findings"], corpus["cases_in_corpus"], corpus["cases_pinned"],
                "`{}`".format(corpus["telemetry_hash"][:12]),
                corpus["load_seconds"], corpus["pipeline_seconds"],
            ]
            for name, corpus in payload["corpora"].items()
        ],
    ) + "\n")

    out.append("## Every case\n")
    for case in cases:
        audit = case["necessity_audit"]
        out.append("### `{}` / `{}`\n".format(case["corpus"], case["case_id"]))
        out.append("*Provenance:* {}. *Answer key:* {}.\n".format(
            case["provenance"], case["label_source"],
        ))
        out.append(case["notes"] + "\n")
        out.append(link_report.table(
            ["", ""],
            [
                ["leading rule", "`{}`".format(case["leading_rule"])],
                ["rules", ", ".join(
                    "`{}` {}".format(r, case["rule_titles"].get(r, ""))
                    for r in case["rule_ids"]
                )],
                ["findings", ", ".join(f"`{f}`" for f in case["finding_ids"])],
                ["evidence ids", "{} -- {}".format(
                    len(case["evidence_ids"]),
                    ", ".join(f"`{e}`" for e in case["evidence_ids"]),
                )],
                ["telemetry hash", "`{}`".format(case["telemetry_hash"])],
                ["selection", case["selection"]],
            ],
        ) + "\n")
        out.append("**Necessity audit.** Domains with materially relevant evidence: "
                   "{}. Eligible at step 0: {} ({} domain specialist(s)). Eligible over "
                   "the whole deterministic run: {}. Independent evidence sources: {} "
                   "({}). Qualifies: **{}**.\n".format(
                       ", ".join(audit["domains"]) or "--",
                       ", ".join(audit["first_step_eligible"]) or "--",
                       audit["first_step_domain_specialists"],
                       ", ".join(audit["whole_run_eligible"]) or "--",
                       audit["independent_evidence_sources"],
                       ", ".join(
                           f"{v} {k}"
                           for k, v in sorted(audit["evidence_sources"].items())
                       ) or "--",
                       "YES" if audit["qualifies"] else "no -- " + audit["failure_reason"],
                   ))
        out.append("*Condition 3 (what synthesis could change):* " + case["condition_3"] + "\n")
        out.append("*Measured synthesis statement:* " + audit["synthesis_statement"] + "\n")
        if case["links"]:
            out.append("**Pre-registered CDER links.**\n")
            out.append(link_report.table(
                ["link", "stage transition", "identity event", "endpoint event", "note"],
                [
                    [
                        "`{}`".format(link["link_id"]), link["stage_transition"],
                        "`{}`{}".format(
                            link["identity"]["event_id"],
                            " (`{}`)".format(link["identity"]["ref"])
                            if link["identity"]["ref"] else "",
                        ),
                        "`{}`{}".format(
                            link["endpoint"]["event_id"],
                            " (`{}`)".format(link["endpoint"]["ref"])
                            if link["endpoint"]["ref"] else "",
                        ),
                        link["note"][:160],
                    ]
                    for link in case["links"]
                ],
            ) + "\n")
        else:
            out.append("**Pre-registered CDER links:** none. CDER on this case is "
                       "`{}`.\n".format(case["cder"]))
        out.append("**Rubric.** Stages ({}): {}. Verdict: **{}**. Next action, written "
                   "before any run: {}\n".format(
                       case["rubric"]["stages_source"],
                       ", ".join(f"`{s}`" for s in case["rubric"]["stages"]),
                       case["rubric"]["verdict"],
                       case["rubric"]["next_action"],
                   ))

    out.append("## Input hashes\n")
    sources = payload["sources"]
    out.append("Injected case directories (every file, sha256 over `path:digest` lines):\n")
    out.append(link_report.table(
        ["case", "directory", "sha256", "files"],
        [
            [case_id, "`{}`".format(entry["directory"]), "`{}`".format(entry["sha256"]),
             len(entry["files"])]
            for case_id, entry in sources["dedale_injected_case_directories"].items()
        ],
    ) + "\n")
    out.append("DEDALE source days, as `reports/m19b/cases/dedale_injected/MANIFEST.json` "
               "records them:\n")
    out.append(link_report.table(
        ["file", "sha256", "bytes"],
        [[name, "`{}`".format(entry["sha256"]), entry["bytes"]]
         for name, entry in sources["dedale_source_files"].items()],
    ) + "\n")
    out.append("flaws.cloud, from `data/external/MANIFEST.json` (fetched {}):\n".format(
        sources["flaws_cloud"]["fetched_on"],
    ))
    out.append(link_report.table(
        ["file", "sha256", "bytes"],
        [[f["path"], "`{}`".format(f["sha256"]), f["bytes"]]
         for f in sources["flaws_cloud"]["files"]],
    ) + "\n")
    out.append(
        "Generator `{}` sha256 `{}` (seed {}); "
        "`data/raw/ground_truth.json` sha256 `{}`.\n".format(
            sources["dedale_generator"]["script"],
            sources["dedale_generator"]["sha256"],
            sources["dedale_generator"]["seed"],
            sources["synthetic_ground_truth_sha256"],
        )
    )

    out.append("## How the links were defined\n")
    for name, rule in payload["cder_link_rules"].items():
        out.append(f"* **{name}**: {rule}")
    out.append("")

    out.append("## Limitations\n")
    for limitation in payload["limitations"]:
        out.append("* " + limitation)
    out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------


EXCLUSIONS = (
    {
        "what": "`dedale_injected:HELDOUT_H1`",
        "reason": (
            "held out until the final evaluation; its answer key is sealed and is not "
            "opened by this script or its tests"
        ),
    },
    {
        "what": "`fixture:cloudtrail` CASE-001",
        "reason": (
            "a shipped test fixture. It qualifies, and it is excluded because a "
            "benchmark built on the fixtures the system is tested against grades its "
            "own homework"
        ),
    },
    {
        "what": "the other 20 M19 cases",
        "reason": (
            "none of them qualifies: `reports/m19b/necessity/AUDIT.md` measured one "
            "domain specialist eligible at every step on each"
        ),
    },
    {
        "what": "the other 277 flaws.cloud cases",
        "reason": "single-domain (control_plane only) -- see the T4 audit's distribution",
    },
)


def cmd_build(args: argparse.Namespace) -> int:
    built, corpora = build_cases(args.external)
    entries = [case.entry for case in built]
    if len(built) != 9:
        raise SystemExit(
            f"the frozen case set has nine cases and this build produced {len(built)}; the set is "
            "fixed by the architect and this script may not change it"
        )
    refuse_if_inputs_moved(args.out_dir / MANIFEST_PATH.name, entries)

    digest = manifest_hash(entries)
    case_payloads = [case.to_dict() for case in built]
    payload: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": m19._head(),
        "case_set_frozen_by": CASE_SET_FROZEN_BY,
        "selection_rule": SELECTION_RULE,
        "excluded": list(EXCLUSIONS),
        "manifest_hash": digest,
        "external": str(args.external),
        "corpora": corpora,
        "cder_link_rules": {
            "dedale_injected:*": (
                "the `links` block each case's `labels.json` pre-registers, written by "
                "scripts/m19b_inject_dedale.py at generation time; native "
                "`host;channel;record_id` refs resolved to ATH event ids by "
                "ath.evaluation.external_labels.resolve_refs, and refused if any ref "
                "names no ingested row"
            ),
            "synthetic:INC-001": INC001_LINK_RULE,
            "flaws_cloud": (
                "none. The corpus has no labels, so no link can be pre-registered and "
                "the CDER column reads " + CDER_UNAVAILABLE
            ),
        },
        "m19_inc001_comparison": compare_inc001(built),
        "limitations": list(LIMITATIONS),
        "sources": source_hashes(args.external),
        "cases": case_payloads,
    }
    payload["benchmark_hash"] = hashlib.sha256(
        json.dumps(
            {"selection_rule": SELECTION_RULE, "cases": case_payloads},
            sort_keys=True, separators=(",", ":"), default=str,
        ).encode("utf-8")
    ).hexdigest()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    m19.write_artifact(args.out_dir / MANIFEST_PATH.name, payload)
    (args.out_dir / MANIFEST_MD.name).write_text(
        render_markdown(payload), encoding="utf-8",
    )
    print(f"\nmanifest_hash  {digest}")
    print("benchmark_hash {}".format(payload["benchmark_hash"]))
    print(f"wrote {args.out_dir / MANIFEST_PATH.name} and {args.out_dir / MANIFEST_MD.name}")

    not_qualifying = [
        case.key for case in built if not case.audit.qualifies
    ]
    if not_qualifying:
        print(
            f"WARNING: {len(not_qualifying)} case(s) do not qualify under docs/m19b-plan.md: {not_qualifying}"
        )
    return 0


def compare_inc001(built: Sequence[BenchmarkCase]) -> dict[str, Any]:
    """Is INC-001's finding set the one M19 pinned, after the correlator change?

    ``reports/m19b/link/BEFORE_AFTER.md`` asserts that replacing the cross-domain
    allowlist added links to this case without changing its membership. Asserting it and
    checking it are different things, so the manifest carries the comparison.
    """
    entry = next(c.entry for c in built if c.key == "synthetic:INC-001")
    m19_manifest = json.loads(
        (ROOT / "reports" / "m19" / "ablation" / "MANIFEST.json").read_text(
            encoding="utf-8",
        )
    )
    pinned = next(
        c for c in m19_manifest["cases"] if c["corpus"] == "synthetic:INC-001"
    )
    return {
        "m19_manifest_hash": m19_manifest["manifest_hash"],
        "case_id": {"m19": pinned["case_id"], "m19b": entry.case_id},
        "finding_ids_equal": list(pinned["finding_ids"]) == list(entry.finding_ids),
        "evidence_ids_equal": list(pinned["evidence_ids"]) == list(entry.evidence_ids),
        "rule_ids_equal": list(pinned["rule_ids"]) == list(entry.rule_ids),
        "telemetry_hash_equal": pinned["telemetry_hash"] == entry.telemetry_hash,
        "m19_finding_ids": list(pinned["finding_ids"]),
        "m19b_finding_ids": list(entry.finding_ids),
        "note": (
            "the M19b correlator change (the cross-domain allowlist replaced by a "
            "channel-family test) is asserted not to change this case's membership; "
            "these four booleans are that assertion, checked"
        ),
    }


# --------------------------------------------------------------------------------------
# run: arm A, twice, over the frozen manifest
# --------------------------------------------------------------------------------------


def read_manifest(out_dir: Path) -> tuple[dict[str, Any], list[CaseManifest], str]:
    """The frozen manifest, refusing one that does not describe itself."""
    payload = json.loads((out_dir / MANIFEST_PATH.name).read_text(encoding="utf-8"))
    entries = load_manifest(payload)
    recomputed = manifest_hash(entries)
    recorded = str(payload.get("manifest_hash", ""))
    if recomputed != recorded:
        raise SystemExit(
            f"MANIFEST.json records {recorded[:12]} but its entries hash to {recomputed[:12]}. The file has been "
            "edited since it was frozen; refusing to run an arm against a manifest that "
            "does not describe itself."
        )
    return payload, entries, recorded


def links_by_case(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    return {
        "{}/{}".format(case["corpus"], case["case_id"]): list(case["links"])
        for case in payload.get("cases", ())
    }


def recovered_links(
    state: dict[str, Any],
    links: Sequence[dict[str, Any]],
    case_evidence_ids: Sequence[str] = (),
) -> dict[str, Any]:
    """Which pre-registered links this row's accepted claims already cite on both sides.

    The plan's definition, applied literally: a link is recovered when **one** accepted
    claim -- a FACT or an INFERENCE, which are the two the verifier accepts with evidence
    -- cites the evidence on both sides of it. Two claims that each cite one side are not
    a recovery: the whole question is whether anything in the investigation joined them.

    Which claim recovered it is recorded beside the count, because the count alone cannot
    distinguish the two things a reader needs to tell apart. A claim that cites two rows
    and says what joining them means is cross-domain synthesis. A claim that cites *every*
    evidence id in the case satisfies the same predicate while making no cross-domain
    statement at all, and would put a recovery in the column for free. So each recovery
    carries its claim's agent, type, and what fraction of the case's evidence that claim
    cited; ``case_evidence_fraction`` at 1.0 is the blanket case. No threshold is applied
    here -- the numbers are reported, and the pre-registration decides what they mean.
    """
    case_evidence = {str(e) for e in case_evidence_ids}
    accepted = [
        claim for claim in state.get("claims", ())
        if claim.get("type") in ("FACT", "INFERENCE")
    ]
    detail: dict[str, Any] = {}
    for link in links:
        left = link["identity"]["event_id"]
        right = link["endpoint"]["event_id"]
        by = []
        for claim in accepted:
            ids = {str(e) for e in (claim.get("evidence_ids") or ())}
            if left in ids and right in ids:
                by.append({
                    "agent": claim.get("agent", ""),
                    "type": claim.get("type", ""),
                    "evidence_ids_cited": len(ids),
                    "case_evidence_fraction": (
                        round(len(ids & case_evidence) / len(case_evidence), 4)
                        if case_evidence else None
                    ),
                    "statement": str(claim.get("statement", ""))[:180],
                })
        if by:
            detail[link["link_id"]] = by
    return {
        "defined": len(links),
        "recovered": len(detail),
        "recovered_link_ids": sorted(detail),
        "cder": round(len(detail) / len(links), 4) if links else None,
        "recovered_by": detail,
        "recovering_agents": sorted({
            entry["agent"] for entries in detail.values() for entry in entries
        }),
    }


def analyse(
    row: CaseResult,
    links: Sequence[dict[str, Any]],
    cder_status: str,
    case_evidence_ids: Sequence[str] = (),
) -> dict[str, Any]:
    """The per-case row the report table is built from."""
    # The *serialised* state, so a reader can recompute every number in this block from
    # the committed file. It is the id-capped copy `to_dict` writes; claims here cite a
    # handful of ids against a 5000-id cap, so capping changes nothing, and computing
    # from a richer object than the artifact carries would produce a figure nobody else
    # can reproduce.
    state = cap_serialised_ids(row.state if isinstance(row.state, dict) else {})
    planner = ((state.get("llm") or {}).get("planner") or {})
    scores = row.scores
    analysis = {
        "corpus": row.corpus,
        "case_id": row.case_id,
        # Read off CaseScores rather than the serialised state: these are the same
        # numbers ath.evaluation.ablation.scoring computed for the row, so the table
        # and the scores file cannot disagree about how many specialists ran.
        "specialists_eligible": scores.specialists_eligible,
        "specialists_run": scores.specialists_run,
        "eligible_never_ran": list(scores.eligible_never_ran),
        "agents_run": list(state.get("agents_run") or ()),
        "steps": scores.steps,
        "status": scores.status,
        "planner_multi_candidate_steps": int(planner.get("multi_candidate_steps", 0)),
        "planner_chosen_by_model": int(planner.get("chosen_by_model", 0)),
        "planner_decisions": dict(planner.get("decisions") or {}),
        "tool_calls": scores.tool_calls,
        "distinct_tools": scores.distinct_tools,
        "facts": scores.facts,
        "inferences": scores.inferences,
        "hypotheses": scores.hypotheses,
        "rejected_claims": scores.rejected_claims,
    }
    if links:
        analysis["cder"] = recovered_links(state, links, case_evidence_ids)
    else:
        analysis["cder"] = {"defined": 0, "recovered": 0, "recovered_link_ids": [],
                            "cder": None, "recovered_by": {}, "recovering_agents": [],
                            "status": cder_status}
    return analysis


def cmd_run(args: argparse.Namespace) -> int:
    payload, entries, digest = read_manifest(args.manifest_dir)
    letter = m19._arm_letter(args.arm)
    if letter != "A":
        raise SystemExit(
            "this script runs arm A only. Arms B and C require a model and belong to "
            "T8, under the M19b environment freeze; running one from here would "
            "produce rows outside it."
        )
    arm = ARM_BUILDERS[m19._arm_name(args.arm)]()
    if arm.requires_model:
        raise SystemExit(f"{arm.name} requires a model; this script is the no-key path")

    by_corpus: dict[str, list[CaseManifest]] = defaultdict(list)
    for entry in entries:
        by_corpus[entry.corpus].append(entry)

    runs: list[list[CaseResult]] = [[], []]
    timing: dict[str, Any] = {}
    for bundle in bundles(args.external):
        corpus_entries = by_corpus.get(bundle.name)
        if not corpus_entries:
            continue
        started = time.perf_counter()
        for index in range(2):
            # A separate investigation per repeat: run_arm builds a fresh toolbox, a
            # fresh orchestrator and a fresh state per case, so repeat 2 shares nothing
            # with repeat 1 but the corpus and the frozen configuration.
            runs[index] += run_arm(
                arm, corpus_entries, bundle.telemetry, bundle.cases,
                manifest_digest=digest, findings=bundle.findings,
                environment=bundle.environment,
                label_scorer=m19._label_scorer(bundle),
            )
        timing[bundle.name] = {
            "load_seconds": round(bundle.load_seconds, 1),
            "pipeline_seconds": round(bundle.pipeline_seconds, 1),
            "arm_seconds_both_repeats": round(time.perf_counter() - started, 1),
            "cases": len(corpus_entries),
        }
        print("{}: {} case(s) x 2 run(s) in {}s".format(
            bundle.name, len(corpus_entries), timing[bundle.name]["arm_seconds_both_repeats"],
        ), flush=True)

    differences = identical(runs[0], runs[1])
    if differences:
        raise SystemExit(
            f"arm A is deterministic and its two runs differ in {len(differences)} place(s): {differences[:5]}. A "
            "baseline that is not reproducible cannot be the baseline anything is "
            "compared against."
        )

    links = links_by_case(payload)
    cder_status = {
        "{}/{}".format(c["corpus"], c["case_id"]): c["cder"] for c in payload["cases"]
    }
    evidence = {
        "{}/{}".format(c["corpus"], c["case_id"]): c["evidence_ids"]
        for c in payload["cases"]
    }
    analysis = [
        analyse(
            row,
            links.get(f"{row.corpus}/{row.case_id}", []),
            cder_status.get(f"{row.corpus}/{row.case_id}", ""),
            evidence.get(f"{row.corpus}/{row.case_id}", ()),
        )
        for row in runs[0]
    ]
    no_choice = [
        a for a in analysis if a["planner_multi_candidate_steps"] == 0
    ]

    record = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "head": m19._head(),
        "arm": arm.to_dict(),
        "scripted": False,
        "manifest_hash": digest,
        "manifest_head": payload.get("head"),
        "benchmark_hash": payload.get("benchmark_hash"),
        "reproducibility": {
            "repeats": 2,
            "compared": True,
            "identical": True,
            "differences": [],
            "note": (
                "wall seconds and wall-clock timestamps are excluded from the "
                "comparison; every claim, tool call, plan-log line and score is included"
            ),
        },
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
        "analysis": analysis,
        "cases_with_no_planner_choice": [a["case_id"] for a in no_choice],
        "m19_inc001_comparison": payload.get("m19_inc001_comparison"),
        "cases": [r.to_dict() for r in runs[0]],
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"arm_{letter}.json"
    m19.refuse_mislabelled_output(out, runs[0])
    m19.write_artifact(out, record)
    print(f"\nwrote {out} ({len(runs[0])} row(s)); two runs IDENTICAL")

    print("\n" + link_report.table(
        ["case", "specialists eligible/run", "planner multi-candidate steps",
         "tool calls", "facts/inf/hyp", "links recovered"],
        [
            [
                "{}/{}".format(a["corpus"], a["case_id"]),
                "{}/{}".format(a["specialists_eligible"], a["specialists_run"]),
                a["planner_multi_candidate_steps"],
                a["tool_calls"],
                "{}/{}/{}".format(a["facts"], a["inferences"], a["hypotheses"]),
                "{}/{}".format(a["cder"]["recovered"], a["cder"]["defined"])
                if a["cder"]["defined"] else a["cder"].get("status", "--"),
            ]
            for a in analysis
        ],
    ))
    if no_choice:
        print(
            "\nWARNING: {} case(s) offered arm A's planner no choice at any step: "
            "{}".format(len(no_choice), [a["case_id"] for a in no_choice])
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="freeze the M19b benchmark manifest")
    p_build.add_argument("--out-dir", type=Path, default=OUT_DIR)
    p_build.add_argument("--external", type=Path, default=DEFAULT_EXTERNAL)
    p_build.set_defaults(func=cmd_build)

    p_run = sub.add_parser(
        "run", help="run arm A over the frozen manifest, twice, asserted identical",
    )
    p_run.add_argument("--arm", default="A")
    p_run.add_argument("--manifest-dir", type=Path, default=OUT_DIR)
    p_run.add_argument("--out-dir", type=Path, default=ABLATION_DIR)
    p_run.add_argument("--external", type=Path, default=DEFAULT_EXTERNAL)
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
