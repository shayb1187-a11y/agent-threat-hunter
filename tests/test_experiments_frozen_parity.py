"""The helpers copied from the M19 scripts into ``ath.experiments.bundles`` behave as the originals.

``pipeline``, ``label_scorer``, ``required_footing_for`` and ``select_synthetic`` were
copied out of ``scripts/m19_ablation.py`` / ``m19b_ablation.py`` so the package does not
import script module bodies. A copy that drifts would put the runner on a different
footing from the frozen rows without any hash noticing; this test runs both on the
fixture corpus and demands the same answer.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import m19_ablation as m19  # noqa: E402
import m19b_ablation as m19b  # noqa: E402
from ath.evaluation.ablation.environment import tool_surface  # noqa: E402
from ath.evaluation.ablation.local import arm_d1  # noqa: E402
from ath.experiments import bundles  # noqa: E402
from test_ablation_harness import corpus, manifest, pipeline  # noqa: F401,E402


def test_the_pipeline_copy_forms_the_same_findings_and_cases(corpus) -> None:
    ours = bundles.pipeline(corpus)
    theirs = m19._pipeline(corpus)
    assert [f.finding_id for f in ours[0]] == [f.finding_id for f in theirs[0]]
    assert [c.case_id for c in ours[1]] == [c.case_id for c in theirs[1]]
    assert [sorted(c.event_ids) for c in ours[1]] == [sorted(c.event_ids) for c in theirs[1]]
    assert set(ours[3]) == set(theirs[3])


def test_the_footing_copy_matches_the_m19b_original(manifest) -> None:
    arm = arm_d1("fake:1b")
    surface = tool_surface()
    digest = manifest[0].telemetry_hash
    assert bundles.required_footing_for(arm, digest, surface) == m19b.required_footing_for(arm, digest, surface)


def test_the_label_scorer_copy_agrees_on_a_corpus_without_an_answer_key(corpus, pipeline) -> None:
    findings, cases, environment = pipeline
    ours = bundles.Bundle(name="fixture", telemetry=corpus, findings=findings, cases=cases, environment=environment)
    theirs = m19.Bundle(name="fixture", telemetry=corpus, findings=findings, cases=cases, environment=environment)
    assert bundles.label_scorer(ours) is None and m19._label_scorer(theirs) is None


def test_the_synthetic_selection_copy_matches_m19_on_every_suite_incident() -> None:
    ours = {b.name: b for b in bundles.synthetic_bundles()}
    theirs = {b.name: b for b in m19.load_bundles(["synthetic"])}
    assert set(ours) == set(theirs)
    for name in sorted(ours):
        selected_a, why_a, detail_a = bundles.select_synthetic(ours[name])
        selected_b, why_b, detail_b = m19.select(theirs[name])
        assert [c.case_id for c in selected_a] == [c.case_id for c in selected_b], name
        assert (why_a, detail_a) == (why_b, detail_b), name
