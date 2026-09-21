"""The M19b benchmark manifest is what it claims to be, checked against the pipeline.

What these tests are for
-------------------------
``scripts/m19b_manifest.py`` freezes nine cases and the claims made about each of them:
a necessity audit, a condition-3 sentence, a set of pre-registered cross-domain links
and an analyst rubric. A frozen benchmark is worth exactly as much as those claims, so
each is a test:

* the case set is **exactly** the nine the architect fixed -- not eight, not ten, and
  not nine different ones;
* every case's necessity audit says it **qualifies**, with at least two *domain*
  specialists eligible at step 0, which is the number that decides whether the planner
  is ever consulted (``reports/m19b/necessity/AUDIT.md``);
* every injected label ref resolves to exactly one ingested row, and every
  pre-registered link's two event ids are the ids a fresh load produces -- an answer key
  with holes would silently shrink the CDER denominator;
* the condition-3 sentence in the manifest is **verbatim** from the case's own
  ``CASE.md``, so the two cannot drift into different claims about one case;
* the two flaws.cloud cases are pinned by member finding ids and principal, and a fresh
  load reproduces them;
* arm A's ``synthetic:INC-001`` row is the same case M19 investigated -- the M19b
  correlator change is asserted not to change its finding set, and this is that
  assertion checked rather than repeated;
* the manifest **refuses** to rebuild when a pinned case's telemetry hash moved.

``HELDOUT_H1`` is never opened. :func:`test_the_sealed_answer_key_is_never_opened` is a
runtime path audit rather than a promise: it records every file the build path opens and
fails if the sealed directory appears among them.
"""

from __future__ import annotations

import builtins
import io
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import m19b_manifest as mm  # noqa: E402
from ath.evaluation.external_labels import (  # noqa: E402
    RESOLVED,
    load_external_labels,
    resolve_labels,
    resolve_refs,
)

MANIFEST_PATH = ROOT / "reports" / "m19b" / "MANIFEST.json"
ARM_A_PATH = ROOT / "reports" / "m19b" / "ablation" / "arm_A.json"
M19_MANIFEST = ROOT / "reports" / "m19" / "ablation" / "MANIFEST.json"
M19_ARM_A = ROOT / "reports" / "m19" / "ablation" / "arm_A.json"
CASE_ROOT = ROOT / "reports" / "m19b" / "cases" / "dedale_injected"

EXPECTED_KEYS: tuple[str, ...] = (
    "synthetic:INC-001/CASE-001",
    "dedale_injected:M1/CASE-001",
    "dedale_injected:M2/CASE-001",
    "dedale_injected:M3/CASE-001",
    "dedale_injected:M4/CASE-001",
    "dedale_injected:L1/CASE-001",
    "dedale_injected:L2/CASE-001",
    "flaws_cloud/CASE-182",
    "flaws_cloud/CASE-256",
)
"""The nine cases, written out rather than derived from the manifest.

A test that read the case set out of the artifact it is testing would pass on any case
set. These are the ``corpus/case_id`` pairs the architect fixed; the flaws.cloud case
numbers are the ones recorded at freeze time, and the manifest's own pin is the finding
ids, which :func:`test_the_flaws_cases_are_pinned_by_finding_ids` checks separately.
"""

RELOAD_VARIABLE = "ATH_M19B_FLAWS_RELOAD"
"""Set to ``1`` to re-load flaws.cloud (1.9M rows, ~6 minutes, ~3 GB) inside the test
suite. Off by default: the committed ``arm_A.json`` already proves a fresh load
reproduced the pin, because ``run_arm`` refuses a case whose findings differ from the
pinned ones, so the reload is a second, much more expensive proof of the same fact."""


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def manifest() -> dict:
    if not MANIFEST_PATH.exists():
        pytest.skip(f"{MANIFEST_PATH} has not been built")
    return _json(MANIFEST_PATH)


@pytest.fixture(scope="module")
def arm_a() -> dict:
    if not ARM_A_PATH.exists():
        pytest.skip(f"{ARM_A_PATH} has not been run")
    return _json(ARM_A_PATH)


def _cases(manifest: dict) -> dict[str, dict]:
    return {f"{c['corpus']}/{c['case_id']}": c for c in manifest["cases"]}


# --------------------------------------------------------------------------------------
# The case set
# --------------------------------------------------------------------------------------


def test_the_case_set_is_exactly_the_nine_the_architect_fixed(manifest):
    assert tuple(_cases(manifest)) == EXPECTED_KEYS, (
        "the M19b case set is frozen: adding, removing or renaming a case after any "
        "measurement is a different benchmark, not a later measurement of this one"
    )
    assert len(manifest["cases"]) == 9


def test_the_manifest_describes_itself(manifest):
    """The recorded hash is the hash of the entries -- else the file was edited."""
    from ath.evaluation.ablation import load_manifest, manifest_hash

    assert manifest_hash(load_manifest(manifest)) == manifest["manifest_hash"]


def test_the_selection_rule_and_exclusions_are_recorded_verbatim(manifest):
    assert manifest["selection_rule"] == mm.SELECTION_RULE
    assert manifest["case_set_frozen_by"] == mm.CASE_SET_FROZEN_BY
    excluded = " ".join(e["what"] for e in manifest["excluded"])
    assert "HELDOUT_H1" in excluded and "fixture:cloudtrail" in excluded, (
        "a case that was considered and excluded is part of the selection rule; "
        "leaving it unsaid makes the set look like the only one available"
    )


# --------------------------------------------------------------------------------------
# Necessity
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_every_case_qualifies_with_two_domain_specialists_at_step_zero(key, manifest):
    """The plan's test, on the plan's own terms, for every case in the set.

    Two *eligible* specialists is not the bar: M19's 21 dead cases each had two eligible
    over the whole run (one domain agent and the ATT&CK mapper) and no choice at any
    step. What matters is how many **domain** specialists are eligible at step 0.
    """
    audit = _cases(manifest)[key]["necessity_audit"]
    assert audit["qualifies"] is True, (
        f"{key}: {audit['failure_reason']}"
    )
    assert audit["two_domains"] and audit["non_redundant"]
    assert audit["synthesis_could_change"]
    assert audit["first_step_domain_specialists"] >= 2, (
        f"{key}: {audit['first_step_domain_specialists']} domain specialist(s) eligible "
        f"at step 0 ({audit['first_step_eligible']}); a case where one specialist can "
        "ever run does not test a crew"
    )
    assert audit["independent_evidence_sources"] >= 2


@pytest.mark.parametrize("key", EXPECTED_KEYS)
def test_every_case_carries_a_condition_three_and_a_rubric(key, manifest):
    case = _cases(manifest)[key]
    assert case["condition_3"].strip()
    rubric = case["rubric"]
    assert rubric["stages"], f"{key}: a rubric with no stages grades nothing"
    assert rubric["verdict"] in {"malicious", "benign", "unknown"}
    assert rubric["next_action"].strip()
    assert rubric["stages_source"].strip()
    if case["corpus"] == "flaws_cloud":
        assert rubric["verdict"] == "unknown", (
            "flaws.cloud has no labels; any verdict but `unknown` would be invented"
        )


def _normalised(text: str) -> str:
    return " ".join(text.split())


@pytest.mark.parametrize("case_id", mm.INJECTED_CASE_IDS)
def test_the_injected_condition_three_is_verbatim_from_the_case_page(case_id):
    """The manifest quotes ``CASE.md``; a paraphrase would be a second, silent claim."""
    sentence = mm.CONDITION_3[f"dedale_injected:{case_id}"]
    page = (CASE_ROOT / case_id / "CASE.md").read_text(encoding="utf-8")
    assert _normalised(sentence) in _normalised(page), (
        f"{case_id}: the manifest's condition-3 sentence is not in its CASE.md"
    )


# --------------------------------------------------------------------------------------
# The answer keys
# --------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def injected_loads() -> dict:
    """Each injected case, re-loaded through the real adapter and pipeline."""
    return {
        case_id: mm.injected_bundle(case_id) for case_id in mm.INJECTED_CASE_IDS
    }


@pytest.mark.parametrize("case_id", mm.INJECTED_CASE_IDS)
def test_every_injected_label_ref_resolves_to_one_ingested_row(case_id, injected_loads):
    bundle = injected_loads[case_id]
    labels = load_external_labels(CASE_ROOT / case_id / "labels.json")
    resolved = resolve_labels(labels, bundle.telemetry)
    assert resolved.resolved_refs == resolved.total_refs, (
        f"{case_id}: {resolved.total_refs - resolved.resolved_refs} of "
        f"{resolved.total_refs} label ref(s) name no single ingested row "
        f"(unresolved {resolved.unresolved}, ambiguous {resolved.ambiguous}). A hole in "
        "the answer key shrinks every denominator computed from it."
    )


@pytest.mark.parametrize("case_id", mm.INJECTED_CASE_IDS)
def test_every_pre_registered_link_resolves_to_the_pinned_event_ids(
    case_id, injected_loads, manifest,
):
    """A link is a pair of *ids*; the manifest records them and a fresh load reproduces."""
    bundle = injected_loads[case_id]
    payload = mm.injected_labels(case_id)
    pinned = {
        link["link_id"]: link
        for link in _cases(manifest)[f"dedale_injected:{case_id}/CASE-001"]["links"]
    }
    refs = [
        side["ref"]
        for entry in payload["links"]
        for side in (entry["identity"], entry["endpoint"])
    ]
    resolved = resolve_refs(refs, bundle.telemetry)
    assert pinned, f"{case_id}: no links pinned"
    for entry in payload["links"]:
        assert entry["link_id"] in pinned
        for domain in ("identity", "endpoint"):
            match = resolved[entry[domain]["ref"]]
            assert match.status == RESOLVED, (
                f"{case_id}/{entry['link_id']}: the {domain} ref is {match.status}"
            )
            assert match.event_id == pinned[entry["link_id"]][domain]["event_id"]


def test_inc001_links_are_the_cross_domain_stage_transition_pairs(manifest):
    """Derived from ground truth's stages, and only where the two domains differ."""
    links = _cases(manifest)["synthetic:INC-001/CASE-001"]["links"]
    truth = json.loads(
        (ROOT / "data" / "raw" / "ground_truth.json").read_text(encoding="utf-8")
    )
    stages = truth["scenarios"]["intrusion"]["stages"]
    assert links, "INC-001 has no pre-registered links"
    for link in links:
        assert link["identity"]["domain"] == "identity"
        assert link["endpoint"]["domain"] == "endpoint"
        assert link["identity"]["event_id"] in stages[link["identity"]["stage"]]["event_ids"]
        assert link["endpoint"]["event_id"] in stages[link["endpoint"]["stage"]]["event_ids"]
        assert link["endpoint"]["stage"] == mm.INC001_TARGET_STAGE
        assert link["identity"]["stage"] in mm.INC001_SOURCE_STAGES


def test_the_real_cases_have_no_links_and_say_so(manifest):
    for key in ("flaws_cloud/CASE-182", "flaws_cloud/CASE-256"):
        case = _cases(manifest)[key]
        assert case["links"] == []
        assert case["cder"] == mm.CDER_UNAVAILABLE, (
            "an unlabelled case's CDER is undefined, not zero: zero would read as a "
            "measurement of an arm rather than of the corpus"
        )
        assert case["labels"]["verdict"] == "unknown"


# --------------------------------------------------------------------------------------
# The sealed case
# --------------------------------------------------------------------------------------


SEALED_LABELS = CASE_ROOT / "HELDOUT_H1" / "SEALED" / "labels.json"


def test_the_sealed_answer_key_is_never_opened(monkeypatch, tmp_path):
    """A runtime path audit of the build path, not a promise about it.

    Every file open the injected-case build performs is recorded and checked against the
    held-out directory. ``HELDOUT_H1`` is excluded from ``INJECTED_CASE_IDS``, which is
    what should keep it out -- this test is what notices when a later edit reaches it
    anyway, through a ``glob``, a directory digest or a manifest lookup.
    """
    opened: list[str] = []
    real_builtin_open = builtins.open
    real_io_open = io.open

    def record(path, *args, **kwargs):
        opened.append(str(path))
        return real_builtin_open(path, *args, **kwargs)

    def record_io(path, *args, **kwargs):
        opened.append(str(path))
        return real_io_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", record)
    monkeypatch.setattr(io, "open", record_io)

    for case_id in mm.INJECTED_CASE_IDS:
        bundle = mm.injected_bundle(case_id)
        mm.build_injected_case(case_id, bundle, mm.select_case(bundle)[0])
    mm.directory_digest(CASE_ROOT / mm.INJECTED_CASE_IDS[0])

    monkeypatch.undo()

    assert opened, "the audit recorded no file opens at all; it is not auditing anything"
    reached = [p for p in opened if mm.SEALED_DIRECTORY in p.replace("/", "\\")
               or mm.SEALED_DIRECTORY in p]
    assert not reached, (
        f"the build opened {len(reached)} path(s) under the held-out case: {reached[:5]}"
    )


def test_the_sealed_answer_key_is_still_sealed_and_unpublished(manifest):
    """The seal exists, and nothing the manifest publishes came out of it."""
    assert SEALED_LABELS.is_file()
    assert "HELDOUT_H1" not in json.dumps(manifest["cases"]), (
        "no case payload may name the held-out case"
    )
    assert "H1" not in {c["labels"].get("injected_case") for c in manifest["cases"]}
    assert mm.SEALED_DIRECTORY not in mm.INJECTED_CASE_IDS


# --------------------------------------------------------------------------------------
# flaws.cloud
# --------------------------------------------------------------------------------------


def test_the_flaws_cases_are_pinned_by_finding_ids(manifest):
    cases = _cases(manifest)
    for pin in mm.FLAWS_PINS:
        key = f"flaws_cloud/{pin.case_id_at_pinning}"
        case = cases[key]
        assert tuple(case["finding_ids"]) == tuple(sorted(pin.finding_ids)), (
            f"{key}: the manifest's member findings are not the pinned ones"
        )
        assert case["labels"]["principal"] == pin.principal
        assert pin.principal in case["selection"]


def test_a_fresh_load_reproduced_the_pinned_flaws_cases(arm_a, manifest):
    """``run_arm`` refuses a case whose findings differ, so a row *is* the proof.

    ``ath.evaluation.ablation.arms._check_inputs`` compares the re-loaded corpus's
    telemetry hash and the case's member finding ids against the manifest before any
    investigation happens, and raises ``ManifestMismatch`` otherwise. A committed arm A
    row for a flaws.cloud case therefore states that a load hours after the freeze
    produced the same findings -- which is what this asserts, without spending six
    minutes and three gigabytes re-proving it.
    """
    rows = {f"{r['corpus']}/{r['case_id']}": r for r in arm_a["cases"]}
    cases = _cases(manifest)
    for pin in mm.FLAWS_PINS:
        key = f"flaws_cloud/{pin.case_id_at_pinning}"
        assert key in rows, f"{key}: arm A has no row, so nothing re-loaded it"
        assert rows[key]["telemetry_hash"] == cases[key]["telemetry_hash"]
        assert rows[key]["manifest_hash"] == manifest["manifest_hash"]


@pytest.mark.skipif(
    os.getenv(RELOAD_VARIABLE) != "1",
    reason=(
        f"set {RELOAD_VARIABLE}=1 to re-load flaws.cloud (1.9M rows, ~6 minutes); the "
        "committed arm A rows already prove a fresh load reproduced the pin"
    ),
)
def test_a_fresh_flaws_load_produces_the_same_finding_ids():
    bundle = mm.flaws_bundle(mm.DEFAULT_EXTERNAL)
    resolved = mm.resolve_flaws_pins(bundle)
    assert [pin.case_id_at_pinning for pin, _ in resolved] == [
        case.case_id for _pin, case in resolved
    ], "a pinned case is no longer the case number it was pinned as"
    for pin, case in resolved:
        assert tuple(sorted(f.finding_id for f in case.findings)) == tuple(
            sorted(pin.finding_ids)
        )
        assert pin.principal in mm.case_principals(bundle.telemetry, case)


# --------------------------------------------------------------------------------------
# Arm A against M19
# --------------------------------------------------------------------------------------


def test_arm_a_inc001_is_the_case_m19_investigated(arm_a, manifest):
    """The M19b correlator change is asserted not to change INC-001's finding set.

    ``reports/m19b/link/BEFORE_AFTER.md`` reports 21 -> 25 links on this case and no
    change to its membership. Asserting that and checking it are different things, so
    this compares the M19b row and entry against M19's committed manifest and arm A.
    """
    m19_manifest = _json(M19_MANIFEST)
    m19_entry = next(
        c for c in m19_manifest["cases"] if c["corpus"] == "synthetic:INC-001"
    )
    entry = _cases(manifest)["synthetic:INC-001/CASE-001"]
    assert list(entry["finding_ids"]) == list(m19_entry["finding_ids"])
    assert list(entry["evidence_ids"]) == list(m19_entry["evidence_ids"])
    assert list(entry["rule_ids"]) == list(m19_entry["rule_ids"])
    assert entry["telemetry_hash"] == m19_entry["telemetry_hash"]
    assert entry["leading_rule"] == m19_entry["leading_rule"]

    m19_row = next(
        r for r in _json(M19_ARM_A)["cases"] if r["corpus"] == "synthetic:INC-001"
    )
    row = next(r for r in arm_a["cases"] if r["corpus"] == "synthetic:INC-001")
    assert row["telemetry_hash"] == m19_row["telemetry_hash"]
    assert row["scores"]["case_evidence_ids"] == m19_row["scores"]["case_evidence_ids"]
    assert row["state"]["agents_run"] == m19_row["state"]["agents_run"]

    recorded = manifest["m19_inc001_comparison"]
    assert recorded["finding_ids_equal"] and recorded["evidence_ids_equal"]
    assert recorded["rule_ids_equal"] and recorded["telemetry_hash_equal"]


def test_arm_a_ran_every_case_twice_and_identically(arm_a):
    assert arm_a["reproducibility"]["repeats"] == 2
    assert arm_a["reproducibility"]["identical"] is True
    assert arm_a["reproducibility"]["differences"] == []
    assert {f"{r['corpus']}/{r['case_id']}" for r in arm_a["cases"]} == set(EXPECTED_KEYS)
    assert arm_a["scripted"] is False
    assert arm_a["arm"]["name"].startswith("A_")


def test_arm_a_link_recovery_is_computed_only_where_links_are_defined(arm_a, manifest):
    cases = _cases(manifest)
    for analysis in arm_a["analysis"]:
        key = f"{analysis['corpus']}/{analysis['case_id']}"
        defined = len(cases[key]["links"])
        assert analysis["cder"]["defined"] == defined
        assert analysis["cder"]["recovered"] <= defined
        if not defined:
            assert analysis["cder"]["cder"] is None
            assert analysis["cder"]["status"] == mm.CDER_UNAVAILABLE


def test_link_recovery_requires_one_claim_to_cite_both_sides():
    """Two claims each citing one half of a link are not a recovery.

    The whole question CDER asks is whether the investigation *joined* the two domains.
    A pair of unrelated claims that happen to mention each side separately is the state
    of affairs the metric exists to distinguish from a recovery.
    """
    link = {
        "link_id": "L",
        "identity": {"event_id": "a"},
        "endpoint": {"event_id": "b"},
    }
    split = {"claims": [
        {"type": "FACT", "evidence_ids": ["a"]},
        {"type": "INFERENCE", "evidence_ids": ["b"]},
    ]}
    joined = {"claims": [{"type": "INFERENCE", "evidence_ids": ["a", "b", "c"]}]}
    hypothesis_only = {"claims": [{"type": "HYPOTHESIS", "evidence_ids": ["a", "b"]}]}

    assert mm.recovered_links(split, [link])["recovered"] == 0
    assert mm.recovered_links(joined, [link])["recovered"] == 1
    assert mm.recovered_links(joined, [link])["cder"] == 1.0
    assert mm.recovered_links(hypothesis_only, [link])["recovered"] == 0, (
        "a HYPOTHESIS is the one claim type allowed to stand without evidence; it is "
        "not an accepted cross-domain finding"
    )
    assert mm.recovered_links({"claims": []}, [])["cder"] is None


def test_a_recovery_records_the_claim_that_made_it():
    """The count cannot tell synthesis apart from a claim that cites the whole case.

    A claim citing every evidence id in the case satisfies the recovery predicate while
    saying nothing about either domain. Arm A does exactly this on every labelled case
    in this benchmark (the ATT&CK mapper's "the case spans N tactics"), so the fraction
    of the case's evidence the recovering claim cited is recorded beside every recovery
    -- without a threshold, because what counts as a blanket citation is the
    pre-registration's decision and not this script's.
    """
    link = {"link_id": "L", "identity": {"event_id": "a"}, "endpoint": {"event_id": "b"}}
    blanket = {"claims": [{
        "type": "INFERENCE", "agent": "attack", "statement": "spans 4 tactics",
        "evidence_ids": ["a", "b", "c", "d"],
    }]}
    pointed = {"claims": [{
        "type": "INFERENCE", "agent": "identity", "statement": "the logon explains the shell",
        "evidence_ids": ["a", "b"],
    }]}
    case_evidence = ["a", "b", "c", "d"]

    wide = mm.recovered_links(blanket, [link], case_evidence)
    narrow = mm.recovered_links(pointed, [link], case_evidence)
    assert wide["recovered"] == narrow["recovered"] == 1, (
        "both satisfy the plan's predicate -- which is the point"
    )
    assert wide["recovered_by"]["L"][0]["case_evidence_fraction"] == 1.0
    assert narrow["recovered_by"]["L"][0]["case_evidence_fraction"] == 0.5
    assert wide["recovering_agents"] == ["attack"]
    assert narrow["recovering_agents"] == ["identity"]


# --------------------------------------------------------------------------------------
# The rebuild guard
# --------------------------------------------------------------------------------------


def test_the_manifest_refuses_to_rebuild_when_a_telemetry_hash_moved(manifest, tmp_path):
    from ath.evaluation.ablation import load_manifest

    entries = load_manifest(manifest)
    moved = json.loads(json.dumps(manifest))
    moved["cases"][0]["telemetry_hash"] = "0" * 64

    differences = mm.input_differences(moved, entries)
    assert differences, "a changed telemetry hash must be reported, not absorbed"
    assert "telemetry hash" in differences[0]

    path = tmp_path / "MANIFEST.json"
    path.write_text(json.dumps(moved), encoding="utf-8")
    with pytest.raises(SystemExit) as excinfo:
        mm.refuse_if_inputs_moved(path, entries)
    assert "refusing to rebuild" in str(excinfo.value)


def test_the_manifest_refuses_a_changed_finding_set_and_a_changed_case_set(manifest):
    from ath.evaluation.ablation import load_manifest

    entries = load_manifest(manifest)

    refindings = json.loads(json.dumps(manifest))
    refindings["cases"][0]["finding_ids"] = ["ATH-000:not-a-finding"]
    assert any("finding ids" in d for d in mm.input_differences(refindings, entries))

    # A case missing from the frozen file but present in the rebuild: the set is fixed,
    # so this is a refusal too, and in the other direction it reports the case that
    # would have been dropped.
    dropped = json.loads(json.dumps(manifest))
    removed = dropped["cases"].pop()
    added = mm.input_differences(dropped, entries)
    assert any("the case set is fixed" in d and removed["case_id"] in d for d in added)

    without = [e for e in entries if e.case_id != removed["case_id"]]
    assert any("absent now" in d for d in mm.input_differences(manifest, without))


def test_an_unchanged_rebuild_is_not_refused(manifest):
    from ath.evaluation.ablation import load_manifest

    assert mm.input_differences(manifest, load_manifest(manifest)) == []


# --------------------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------------------


def test_no_case_is_described_as_more_real_than_it_is(manifest):
    """Six of the nine are constructed, and the manifest has to say so on every row."""
    for key, case in _cases(manifest).items():
        if key.startswith("dedale_injected:"):
            assert case["provenance"] == mm.PROVENANCE_INJECTED
            assert "injected" in case["provenance"]
            assert case["labels"]["provenance"] == "real+injected"
        elif key.startswith("synthetic:"):
            assert case["provenance"] == mm.PROVENANCE_SYNTHETIC
        else:
            assert case["provenance"] == mm.PROVENANCE_REAL
            assert case["label_source"] == "none (unlabelled corpus)"


def test_the_input_hashes_cover_every_committed_case_directory(manifest):
    directories = manifest["sources"]["dedale_injected_case_directories"]
    assert tuple(directories) == mm.INJECTED_CASE_IDS
    for case_id, entry in directories.items():
        digest, files = mm.directory_digest(CASE_ROOT / case_id)
        assert digest == entry["sha256"], f"{case_id}: the case directory has changed"
        assert files == entry["files"]
    assert manifest["sources"]["flaws_cloud"]["files"], (
        "the flaws.cloud tar's digest comes from data/external/MANIFEST.json and is the "
        "only statement about which bytes the real cases were built from"
    )
