"""The M19b Route A cases are what they claim to be, measured against the pipeline.

What these tests are for
-------------------------
``scripts/m19b_inject_dedale.py`` writes seven cases under
``reports/m19b/cases/dedale_injected/``: real benign DEDALE Winlogbeat hours with a
labelled endpoint x identity chain injected into them. A constructed benchmark is worth
exactly as much as the claims made about it, so each claim is a test:

* the committed bytes are the bytes the manifest describes, and the manifest was written
  by the script that is committed beside them;
* every case loads through the real adapter with no normalisation issues;
* every case fires the rules it was designed to fire -- no more, which is the part that
  usually breaks, because an injected row can trip a rule nobody was thinking about;
* every case correlates into **one** case carrying both an identity finding and an endpoint
  finding, which is the whole point and the only cross-domain pair this architecture can
  form;
* ``ath.evaluation.necessity.audit_case`` marks that case qualifying with two domain
  specialists eligible at step 0 -- the plan's own test, run by the plan's own code;
* every label ref resolves to exactly one ingested row, so the answer key has no holes;
* the background *without* the injected rows raises nothing at all, which is what makes
  the labels complete rather than merely present;
* regeneration from the seed is byte-identical.

``HELDOUT_H1`` is touched only by hash. No test in this file reads its labels, its stages
or its links, and no test runs the hunting pipeline over it: the case is held until the
final evaluation. :func:`test_the_held_out_case_is_only_ever_hashed_here` asserts that the
parametrised bodies below cannot reach it.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from ath.correlation import correlate  # noqa: E402
from ath.environment import build_environment_model  # noqa: E402
from ath.evaluation.external_labels import load_external_labels, resolve_labels  # noqa: E402
from ath.evaluation.necessity import DOMAIN_SPECIALISTS, audit_case  # noqa: E402
from ath.hunting import HuntConfig, run_hunt  # noqa: E402
from ath.schema import (  # noqa: E402
    EVENT_CONTROL,
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
    TABLE_COLUMNS,
)
from ath.telemetry.loader import Telemetry  # noqa: E402
from ath.telemetry.winlogbeat_source import WinlogbeatSource  # noqa: E402
from ath.triage import assess_findings, set_aside_ids  # noqa: E402
from m19b_inject_dedale import (  # noqa: E402
    CASES,
    DAYS,
    DEFAULT_EXTERNAL,
    DEFAULT_SEED,
)

CASE_ROOT = ROOT / "reports" / "m19b" / "cases" / "dedale_injected"
MANIFEST_PATH = CASE_ROOT / "MANIFEST.json"
SCRIPT = ROOT / "scripts" / "m19b_inject_dedale.py"

CASE_IDS = [spec.case_id for spec in CASES if not spec.sealed]
"""The cases tests may look at. The sealed case is deliberately absent."""

SEALED_ID = next(spec.case_id for spec in CASES if spec.sealed)

IDENTITY_RULES = frozenset({"ATH-005", "ATH-006"})
ENDPOINT_RULES = frozenset({"ATH-007"})

MAX_CASE_BYTES = 4 * 1024 * 1024
"""A case a reviewer cannot open is a case nobody checks. The largest committed case is
~2.1 MB; this bound exists so a future edit that pulls in a boot hour of thirty hosts fails
here rather than in a pull request."""


# --------------------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def manifest() -> dict:
    assert MANIFEST_PATH.is_file(), (
        f"{MANIFEST_PATH} is missing; regenerate with "
        "`python scripts/m19b_inject_dedale.py`"
    )
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _telemetry_of(tables: dict) -> Telemetry:
    """Canonical telemetry from an adapter's tables, tolerating omitted tables."""
    def table(event_type: str):
        frame = tables.get(event_type)
        if frame is None:
            return pd.DataFrame(columns=list(TABLE_COLUMNS[event_type]))
        return frame

    return Telemetry(
        processes=table(EVENT_PROCESS), network=table(EVENT_NETWORK),
        logons=table(EVENT_LOGON), controls=table(EVENT_CONTROL),
    )


def _load(directory: Path):
    result = WinlogbeatSource(directory).load()
    return result, _telemetry_of(result.tables)


def _pipeline(telemetry: Telemetry):
    """The deterministic pipeline, exactly as ``scripts/m19_ablation.py`` runs it."""
    hunt = run_hunt(telemetry, config=HuntConfig())
    environment = build_environment_model(telemetry)
    assessments = assess_findings(hunt.findings, environment)
    cases = correlate(hunt.findings, telemetry, set_aside=set_aside_ids(assessments))
    return list(hunt.findings), list(cases), environment


@pytest.fixture(scope="module")
def investigated() -> dict[str, tuple]:
    """Load, hunt, triage and correlate each open case once; every test reads this."""
    out: dict[str, tuple] = {}
    for case_id in CASE_IDS:
        result, telemetry = _load(CASE_ROOT / case_id / "winlogbeat")
        findings, cases, environment = _pipeline(telemetry)
        out[case_id] = (result, telemetry, findings, cases, environment)
    return out


def _labels(case_id: str) -> dict:
    return json.loads((CASE_ROOT / case_id / "labels.json").read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------------------
# The manifest describes the committed bytes
# --------------------------------------------------------------------------------------


def test_every_file_hashes_to_what_the_manifest_says(manifest):
    """A manifest that has drifted from its files documents a set nobody has."""
    for case_id, entry in manifest["cases"].items():
        case_dir = CASE_ROOT / entry["directory"]
        for name, digest in entry["files"].items():
            path = case_dir / name
            assert path.is_file(), f"{case_id}: {name} named in the manifest is missing"
            assert _sha256(path) == digest, f"{case_id}: {name} does not match its hash"


def test_the_manifest_names_the_script_that_is_committed(manifest):
    """"Generation-script sha256 at commit time" is only a claim if it is checked.

    An edit to the generator that is not followed by a regeneration leaves a manifest
    describing bytes the committed script no longer produces.
    """
    assert manifest["script"] == "scripts/m19b_inject_dedale.py"
    assert manifest["script_sha256"] == hashlib.sha256(SCRIPT.read_bytes().replace(b"\r\n", b"\n")).hexdigest(), (
        "the generator has changed since the cases were written; rerun "
        "`python scripts/m19b_inject_dedale.py`"
    )


def test_no_case_directory_holds_a_file_the_manifest_does_not_name(manifest):
    for entry in manifest["cases"].values():
        case_dir = CASE_ROOT / entry["directory"]
        on_disk = {
            str(p.relative_to(case_dir)).replace("\\", "/")
            for p in case_dir.rglob("*") if p.is_file()
        }
        assert on_disk == set(entry["files"]), (
            f"{entry['directory']}: files on disk and files in the manifest disagree"
        )


def test_the_provenance_is_never_shortened_to_real(manifest):
    """The one sentence this whole directory is not allowed to get wrong."""
    assert manifest["provenance"] == "real+injected"
    for entry in manifest["cases"].values():
        assert entry["provenance_note"] == (
            "real benign DEDALE background + injected attack rows"
        )
        text = (CASE_ROOT / entry["directory"] / "CASE.md").read_text(encoding="utf-8")
        assert "real benign DEDALE background + injected attack rows" in text
        assert "DEDALE (INRIA/IRISA PIRAT)" in text, "CC BY 4.0 requires the attribution"


def test_the_committed_bytes_survive_a_checkout_anywhere(manifest):
    """LF on disk, and a ``.gitattributes`` that stops git rewriting it.

    ``core.autocrlf`` is on in this checkout. Without the ``-text`` attribute git would
    hand a Linux clone LF and a Windows clone CRLF for the same blob, and exactly one of
    them would match the digests in ``MANIFEST.json`` -- a manifest that only verifies on
    the machine that wrote it verifies nothing. This also keeps each background line
    byte-identical to the DEDALE line it came from, which is the provenance claim
    ``PROVENANCE.md`` makes.
    """
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "reports/m19b/cases/dedale_injected/** -text" in attributes

    for entry in manifest["cases"].values():
        case_dir = CASE_ROOT / entry["directory"]
        for name in entry["files"]:
            raw = (case_dir / name).read_bytes()
            assert b"\r\n" not in raw, f"{entry['directory']}/{name} was written with CRLF"


def test_each_case_stays_small_enough_to_read(manifest):
    for case_id, entry in manifest["cases"].items():
        case_dir = CASE_ROOT / entry["directory"]
        total = sum(p.stat().st_size for p in case_dir.rglob("*") if p.is_file())
        assert total <= MAX_CASE_BYTES, f"{case_id} is {total / 1e6:.1f} MB"


# --------------------------------------------------------------------------------------
# Each open case, against the pipeline
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("case_id", CASE_IDS + [SEALED_ID])
def test_every_telemetry_line_is_one_record_in_dedales_own_formatting(case_id, manifest):
    """The provenance claim, checked on the committed bytes.

    ``PROVENANCE.md`` says a background line here is byte-identical to its DEDALE source
    line minus the ``message`` field. The half of that which can be checked without the
    external dataset is the formatting: ``json.dumps`` round-trips DEDALE's separators
    exactly, so a line that does not survive a round-trip was not written the way DEDALE
    writes one. ``message`` must be gone from every line, injected rows included -- a
    rendered copy of ``event_data`` on an injected row would be a second, unmaintained
    description of it.

    The sealed case is included: this reads formatting, not content.
    """
    directory = manifest["cases"][case_id]["directory"]
    for path in sorted((CASE_ROOT / directory / "winlogbeat").glob("*.jsonl")):
        text = path.read_text(encoding="utf-8")
        assert text.endswith("\n")
        for number, line in enumerate(text.splitlines(), start=1):
            record = json.loads(line)
            assert "message" not in record, f"{path.name}:{number} still carries `message`"
            assert json.dumps(record) == line, (
                f"{path.name}:{number} is not in DEDALE's own JSON formatting"
            )


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_the_case_loads_through_the_real_adapter_without_issues(case_id, investigated):
    result, telemetry, _, _, _ = investigated[case_id]
    assert not result.issues, (
        f"{case_id}: the adapter reported normalisation issues on rows this script wrote: "
        f"{[str(i) for i in result.issues[:3]]}"
    )
    assert not telemetry.processes.empty and not telemetry.logons.empty, (
        f"{case_id}: a cross-domain case needs rows in both tables"
    )


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_the_case_fires_exactly_the_rules_it_was_built_for(case_id, investigated, manifest):
    """Both directions matter.

    Missing a rule means the case does not test what it says. Firing an extra one means an
    injected row tripped something nobody designed for, and the case's labels no longer
    describe everything the pipeline saw.
    """
    _, _, findings, _, _ = investigated[case_id]
    expected = manifest["cases"][case_id]["parameters"]["expected_rules"]
    assert sorted({f.rule_id for f in findings}) == sorted(expected)
    assert len(findings) == manifest["cases"][case_id]["parameters"]["expected_findings"]


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_the_case_correlates_into_one_cross_domain_case(case_id, investigated):
    """One case, both domains in it, and joined by the only signal that can span them."""
    _, _, findings, cases, _ = investigated[case_id]
    assert len(cases) == 1, f"{case_id}: expected one case, got {len(cases)}"
    case = cases[0]
    assert len(case.findings) == len(findings), (
        f"{case_id}: a finding was left out of the case"
    )
    rules = set(case.rule_ids)
    assert rules & IDENTITY_RULES, f"{case_id}: no identity finding in the case"
    assert rules & ENDPOINT_RULES, f"{case_id}: no endpoint finding in the case"
    signals = {s.split("(")[0] for link in case.links for s in link.signals}
    assert "auth_then_exec" in signals, (
        f"{case_id}: the identity and endpoint findings are in one case without the "
        "auth_then_exec signal, so something other than the designed link joined them"
    )


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_the_case_qualifies_under_the_plans_necessity_test(case_id, investigated):
    """The plan's three conditions, scored by the plan's own code rather than asserted."""
    _, telemetry, findings, cases, environment = investigated[case_id]
    audit = audit_case(
        cases[0], corpus=f"dedale_injected:{case_id}", provenance="real+injected",
        telemetry=telemetry, findings=findings, cases=cases, environment=environment,
    )
    assert audit.qualifies, f"{case_id}: {audit.failure_reason}"
    assert set(audit.domains) == {"endpoint", "identity"}
    at_step_0 = [n for n in audit.first_step_eligible if n in DOMAIN_SPECIALISTS]
    assert len(at_step_0) >= 2, (
        f"{case_id}: only {at_step_0} eligible at step 0, so the planner is never consulted "
        "-- the exact condition that made M19's ablation unreadable"
    )
    assert audit.independent_evidence_sources >= 2


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_every_label_ref_resolves_to_exactly_one_ingested_row(case_id, investigated):
    _, telemetry, _, _, _ = investigated[case_id]
    labels = load_external_labels(CASE_ROOT / case_id / "labels.json")
    resolved = resolve_labels(labels, telemetry)
    assert resolved.to_dict()["unresolved"] == {}, (
        f"{case_id}: labelled rows the pipeline never ingested"
    )
    assert resolved.to_dict()["ambiguous"] == {}, (
        f"{case_id}: a ref matched more than one row, so the answer key is not a key"
    )
    assert resolved.resolved_refs == resolved.total_refs


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_the_labels_cover_every_injected_record_and_nothing_else(case_id, manifest):
    entry = manifest["cases"][case_id]
    labelled = {
        ref
        for scenario in _labels(case_id)["scenarios"].values()
        for stage in scenario["stages"].values()
        for ref in stage["refs"]
    }
    assert labelled == {row["ref"] for row in entry["injected_record_ids"]}
    assert len(labelled) == entry["injected_count"]


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_the_look_alikes_are_labelled_benign_and_the_rest_malicious(case_id, manifest):
    """A benign look-alike counted as an attack is the measurement bug the field exists for."""
    labels = _labels(case_id)
    (scenario,) = labels["scenarios"].values()
    assert scenario["malicious"] is manifest["cases"][case_id]["parameters"]["malicious"]
    assert scenario["malicious"] == (not case_id.startswith("L"))


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_each_pre_registered_link_pairs_one_logon_row_with_one_process_row(
    case_id, investigated
):
    """CDER scores these pairs, so each side has to name a real row in the stated domain.

    The first link of every case is also asserted to be reachable from the case's own
    evidence: both of its rows are cited by a finding, so a deterministic arm has the
    chance to recover it. Later links deliberately point at rows **no finding cites** --
    the commands run under the shell -- which is what makes them a measurement of
    investigation rather than of detection.
    """
    _, telemetry, _, cases, _ = investigated[case_id]
    logon_refs = dict(zip(telemetry.logons["source_ref"], telemetry.logons["event_id"]))
    process_refs = dict(zip(telemetry.processes["source_ref"], telemetry.processes["event_id"]))

    def _find(table: dict, ref: str) -> str:
        wanted = {p for p in ref.split(";") if p}
        hits = [e for r, e in table.items() if wanted <= {p for p in str(r).split(";") if p}]
        assert len(hits) == 1, f"{case_id}: {ref} matched {len(hits)} rows"
        return hits[0]

    links = _labels(case_id)["links"]
    assert links, f"{case_id}: no cross-domain link was pre-registered"
    case_events = set(cases[0].event_ids)
    for index, link in enumerate(links):
        assert link["identity"]["domain"] == "identity"
        assert link["endpoint"]["domain"] == "endpoint"
        identity_event = _find(logon_refs, link["identity"]["ref"])
        endpoint_event = _find(process_refs, link["endpoint"]["ref"])
        if index == 0:
            assert {identity_event, endpoint_event} <= case_events, (
                f"{case_id}: the primary link is not citable from the case's own evidence"
            )


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_the_background_alone_raises_nothing(case_id, tmp_path, investigated):
    """Remove exactly the labelled rows and the same hours must produce no finding.

    This is what makes the labels complete rather than merely present: every finding a case
    raises is caused by a row the answer key names. It is computed from the committed case
    files rather than by regenerating, so it holds wherever the tests run -- ``data/external``
    is gitignored and usually absent.
    """
    labelled = {
        frozenset(p for p in ref.split(";") if p)
        for scenario in _labels(case_id)["scenarios"].values()
        for stage in scenario["stages"].values()
        for ref in stage["refs"]
    }
    out = tmp_path / "winlogbeat"
    out.mkdir()
    removed = 0
    for source in sorted((CASE_ROOT / case_id / "winlogbeat").glob("*.jsonl")):
        kept: list[str] = []
        for line in source.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            winlog = record["winlog"]
            key = frozenset({
                f"host={record['host']['name']}",
                f"channel={winlog['channel']}",
                f"record_id={winlog['record_id']}",
            })
            if key in labelled:
                removed += 1
                continue
            kept.append(line)
        (out / source.name).write_text("\n".join(kept) + "\n", encoding="utf-8")

    assert removed == len(labelled)
    _, telemetry = _load(out)
    findings, cases, _ = _pipeline(telemetry)
    assert findings == [], (
        f"{case_id}: the benign background raises {[f.rule_id for f in findings]} on its "
        "own, so the labels do not account for every finding in the case"
    )
    assert cases == []


# --------------------------------------------------------------------------------------
# The held-out case
# --------------------------------------------------------------------------------------


def test_the_held_out_case_is_only_ever_hashed_here(manifest):
    """Its labels are sealed: this file checks the seal and never opens it.

    ``CASE_IDS`` drives every parametrised body above and does not contain the sealed case,
    so no test loads its telemetry, hunts over it, or reads its stages. What is asserted is
    that the seal exists and that the manifest publishes its digest and nothing else.
    """
    assert SEALED_ID not in CASE_IDS
    entry = manifest["cases"][SEALED_ID]
    assert entry["sealed"] is True
    sealed = CASE_ROOT / entry["directory"] / "SEALED" / "labels.json"
    assert sealed.is_file()
    assert entry["files"]["SEALED/labels.json"] == _sha256(sealed)
    assert isinstance(entry["injected_record_ids"], str), (
        "the sealed case's injected record ids must not be published in the manifest"
    )
    assert isinstance(entry["expected_rules"], str)
    assert not (CASE_ROOT / entry["directory"] / "labels.json").exists(), (
        "an unsealed copy of the held-out answer key defeats the point of the seal"
    )


# --------------------------------------------------------------------------------------
# Regeneration
# --------------------------------------------------------------------------------------


def _day_files_present() -> bool:
    return all(
        (DEFAULT_EXTERNAL / "dedale" / "winlogbeat" / day / f"{day}_{date}.jsonl").is_file()
        for day, date in DAYS.items()
    )


@pytest.mark.skipif(
    not _day_files_present(),
    reason="DEDALE day files are not present (data/external is gitignored); regeneration "
           "cannot be checked here",
)
def test_regeneration_from_the_seed_is_byte_identical(tmp_path, manifest):
    """The seed is a claim about reproducibility, so it is run, not asserted.

    The sealed case is regenerated too and compared by digest only -- the same thing the
    manifest does, and no more.
    """
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--out", str(tmp_path), "--seed", str(DEFAULT_SEED)],
        capture_output=True, text=True,
    )
    assert completed.returncode == 0, completed.stderr

    for case_id, entry in manifest["cases"].items():
        for name, digest in entry["files"].items():
            regenerated = tmp_path / entry["directory"] / name
            assert regenerated.is_file(), f"{case_id}: {name} was not regenerated"
            assert _sha256(regenerated) == digest, (
                f"{case_id}: {name} differs on regeneration from seed {DEFAULT_SEED}"
            )
