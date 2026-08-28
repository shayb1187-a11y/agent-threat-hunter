"""Tests for analyst feedback storage and triage agreement metrics.

Two properties matter most and are asserted directly: the log is append-only (a
verdict is a fact about what someone concluded, and history is evidence), and
abstention is never scored as agreement (otherwise the safest way to look accurate
would be to have no opinion about anything).
"""

from __future__ import annotations

import json

import pytest

from ath.triage import (
    AnalystVerdict,
    Disposition,
    FeedbackStore,
    Verdict,
    score_feedback,
)


@pytest.fixture
def store(tmp_path):
    return FeedbackStore(tmp_path / "feedback.jsonl")


def _v(finding_id, verdict, disposition, rule="ATH-002", analyst="sam"):
    return AnalystVerdict(
        finding_id=finding_id, rule_id=rule, verdict=verdict,
        analyst=analyst, system_disposition=disposition,
    )


# ======================================================================================
# Storage
# ======================================================================================


def test_missing_log_reads_as_empty(store) -> None:
    """A new deployment has no feedback; that is normal, not an error."""
    assert store.all_verdicts() == []
    assert store.current() == {}


def test_verdicts_round_trip(store) -> None:
    store.record(_v("ATH-002:e1", Verdict.FALSE_POSITIVE, Disposition.LIKELY_BENIGN))
    restored = store.all_verdicts()
    assert len(restored) == 1
    assert restored[0].verdict is Verdict.FALSE_POSITIVE
    assert restored[0].system_disposition is Disposition.LIKELY_BENIGN


def test_log_is_append_only(store) -> None:
    """A revised opinion must not erase the original.

    An analyst changing their mind is itself information: a store that overwrote
    history could not tell "we were right the first time" from "we were never wrong".
    """
    store.record(_v("ATH-002:e1", Verdict.FALSE_POSITIVE, Disposition.LIKELY_BENIGN))
    store.record(_v("ATH-002:e1", Verdict.TRUE_POSITIVE, Disposition.LIKELY_BENIGN))

    assert len(store.all_verdicts()) == 2, "history was overwritten"
    current = store.current()
    assert len(current) == 1
    assert current["ATH-002:e1"].verdict is Verdict.TRUE_POSITIVE


def test_malformed_line_costs_one_record_not_the_history(store) -> None:
    store.record(_v("ATH-002:e1", Verdict.FALSE_POSITIVE, Disposition.LIKELY_BENIGN))
    with store.path.open("a", encoding="utf-8") as handle:
        handle.write("{not json at all\n")
    store.record(_v("ATH-004:e2", Verdict.TRUE_POSITIVE, Disposition.LIKELY_MALICIOUS))

    assert len(store.all_verdicts()) == 2


def test_stored_records_are_plain_json(store) -> None:
    """The log must stay readable with a text editor when something has gone wrong."""
    store.record(_v("ATH-002:e1", Verdict.FALSE_POSITIVE, Disposition.LIKELY_BENIGN))
    line = store.path.read_text(encoding="utf-8").strip()
    assert json.loads(line)["finding_id"] == "ATH-002:e1"


# ======================================================================================
# Agreement scoring
# ======================================================================================


def test_agreement_and_disagreement_are_counted() -> None:
    metrics = score_feedback([
        _v("a", Verdict.FALSE_POSITIVE, Disposition.LIKELY_BENIGN),      # agree
        _v("b", Verdict.TRUE_POSITIVE, Disposition.LIKELY_MALICIOUS),    # agree
        _v("c", Verdict.TRUE_POSITIVE, Disposition.LIKELY_BENIGN),       # disagree
    ])
    assert metrics.scored == 3
    assert metrics.agreed == 2
    assert metrics.disagreed == 1


def test_abstention_is_never_scored_as_agreement() -> None:
    """`needs_review` is the system declining to call it, not a correct answer.

    Counting it as agreement would make abstaining from everything the highest-scoring
    strategy, which is why `opinion_rate` is reported beside `agreement_rate`.
    """
    metrics = score_feedback([
        _v("a", Verdict.FALSE_POSITIVE, Disposition.NEEDS_REVIEW),
        _v("b", Verdict.TRUE_POSITIVE, Disposition.NEEDS_REVIEW),
    ])
    assert metrics.scored == 0
    assert metrics.agreed == 0
    assert metrics.system_had_no_opinion == 2
    assert metrics.opinion_rate == 0.0


def test_undetermined_verdict_is_not_scored() -> None:
    """"We could not tell" is a real outcome and must not become a grade."""
    metrics = score_feedback([
        _v("a", Verdict.UNDETERMINED, Disposition.LIKELY_BENIGN),
    ])
    assert metrics.scored == 0
    assert metrics.system_had_no_opinion == 1


def test_benign_true_positive_counts_as_agreement_with_benign() -> None:
    """Authorised activity the rule correctly described is not a triage failure.

    The remedy differs from a false positive -- the rule needs an exception, not a fix
    -- but calling it benign was the right call.
    """
    metrics = score_feedback([
        _v("a", Verdict.BENIGN_TRUE_POSITIVE, Disposition.LIKELY_BENIGN),
    ])
    assert metrics.agreed == 1


def test_dangerous_disagreement_is_tracked_separately() -> None:
    """Calling a confirmed threat benign is not comparable to other mistakes.

    Every other error costs an analyst time; this one tells them to ignore a live
    intrusion, so one instance deserves more attention than any aggregate rate.
    """
    metrics = score_feedback([
        _v("safe", Verdict.FALSE_POSITIVE, Disposition.LIKELY_MALICIOUS),
        _v("bad", Verdict.TRUE_POSITIVE, Disposition.LIKELY_BENIGN),
    ])
    assert metrics.disagreed == 2
    assert metrics.dangerous_disagreements == ("bad",)


def test_noisiest_rules_reflect_confirmed_false_positives() -> None:
    """Measured false-positive cost from real verdicts, not estimated from a fixture."""
    metrics = score_feedback([
        _v("a", Verdict.FALSE_POSITIVE, Disposition.LIKELY_BENIGN, rule="ATH-003"),
        _v("b", Verdict.FALSE_POSITIVE, Disposition.LIKELY_BENIGN, rule="ATH-003"),
        _v("c", Verdict.FALSE_POSITIVE, Disposition.LIKELY_BENIGN, rule="ATH-002"),
        _v("d", Verdict.TRUE_POSITIVE, Disposition.LIKELY_MALICIOUS, rule="ATH-004"),
    ])
    assert metrics.noisiest_rules == [("ATH-003", 2), ("ATH-002", 1)]
    assert all(rule != "ATH-004" for rule, _ in metrics.noisiest_rules)


def test_metrics_serialise() -> None:
    metrics = score_feedback([
        _v("a", Verdict.FALSE_POSITIVE, Disposition.LIKELY_BENIGN),
    ])
    payload = json.loads(json.dumps(metrics.to_dict()))
    assert payload["agreement_rate"] == 1.0


def test_feedback_does_not_alter_detection(store) -> None:
    """Recording a verdict must not change what fires next run.

    A system that silently re-tuned on analyst clicks would drift unauditably, and an
    attacker who got one finding dismissed would train it to dismiss the next.
    """
    from ath.hunting import run_hunt
    from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
    from ath.telemetry.loader import load_telemetry

    tables, gt = generate_telemetry(GeneratorConfig())
    write_telemetry(tables, gt, store.path.parent)
    telemetry = load_telemetry(store.path.parent)

    before = {f.finding_id for f in run_hunt(telemetry).findings}
    store.record(_v(sorted(before)[0], Verdict.FALSE_POSITIVE, Disposition.LIKELY_BENIGN))
    after = {f.finding_id for f in run_hunt(telemetry).findings}
    assert before == after
