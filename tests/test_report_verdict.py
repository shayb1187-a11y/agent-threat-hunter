"""The report's verdict, investigation tree, reasoning summary, and HTML rendering.

What these tests protect, and why each matters:

* **The verdict never overstates a run.** An operational run that did not complete is
  scored as ``abstain`` downstream; the report must instead say *Incomplete* and give the
  recorded reasons, or a reader would take a crashed model for a considered abstention.
  A deterministic run issues no disposition, and the verdict says that too.
* **No confidence number appears anywhere near a verdict.** This system computes none;
  a percentage in the verdict block would be invented.
* **Model-written text is attributed and its citations marked.** The reasoning summary
  quotes the model; it must never read as a verified finding.
* **Untrusted strings cannot become markup.** Command lines are attacker-controlled and
  model output is unconstrained; both reach the HTML page and both must be escaped.

The runs are the committed synthetic auth-execution development scenarios, driven by
scripted clients explicitly labelled as such -- plumbing, not evidence about any model.
"""

from __future__ import annotations

import json
import re
from dataclasses import fields, replace

import pytest

from ath.agent.claims import Claim, ClaimType
from ath.agent.llm import ScriptedLLM
from ath.agent.operational import EvidenceProfile, investigate_operational
from ath.evaluation import auth_execution as pilot
from ath.reporting import (
    IndexEntry,
    ModelExplanation,
    Verdict,
    audit_calibration,
    build_report,
    render_html,
    render_index,
    render_markdown,
)
from ath.reporting.models import EvidenceAppendixEntry, InvestigationStep
from ath.reporting.verdict import (
    MODEL_TEXT_NOTE,
    NO_CONFIDENCE_NOTE,
    build_verdict,
    no_reasoning_note,
)

# Seed events of development sample-01: a failed logon, the later success, and the
# PsExec-style cmd.exe. All three are in the case the investigation starts from.
FAILURE, SUCCESS, SERVICE_CMD = "72d5a08e0d2a8522ca5a", "0f504253fd98db142c3c", "703eeb16d25835efecb7"
PAYLOAD = '<script>alert(1)</script>" onmouseover="alert(2)'


def _answer(disposition, explanations=(), next_probe="none", reason=""):
    return json.dumps({
        "explanations": list(explanations), "evidence_gap": "what job.cmd did is not observed",
        "next_probe": next_probe, "probe_reason": reason, "disposition": disposition,
    })


def _explanation(label, statement, evidence, assertions=()):
    return {"label": label, "statement": statement, "evidence": list(evidence),
            "assertions": list(assertions)}


MALICIOUS = _explanation(
    "malicious", "Password guessing succeeded and was followed by service-based execution.",
    [FAILURE, SUCCESS, SERVICE_CMD],
    [{"kind": "auth_outcome", "event_id": SUCCESS, "expected": "success"},
     {"kind": "before", "event_id": FAILURE, "other_event_id": SUCCESS}],
)


@pytest.fixture(scope="module")
def scenario():
    return pilot.scenarios("dev")[0]


@pytest.fixture(scope="module")
def prepared(scenario):
    return pilot.prepare(scenario)


def _run(scenario, prepared, responses, *, model=None):
    findings, case, environment = prepared
    llm = ScriptedLLM(responses=responses) if responses is not None else None
    state = investigate_operational(case, scenario.telemetry, findings, llm=llm,
                                    profile=EvidenceProfile(), environment=environment)
    return state, build_report(state, scenario.telemetry, model=model)


@pytest.fixture(scope="module")
def malicious(scenario, prepared):
    probe = _answer("abstain", [MALICIOUS], next_probe="P2",
                    reason="account history distinguishes guessing from a stale password")
    return _run(scenario, prepared, [probe, _answer("malicious", [MALICIOUS])],
                model="scripted-test-client")


@pytest.fixture(scope="module")
def benign(scenario, prepared):
    explanation = _explanation("benign", "An administrator's maintenance job.", [SUCCESS])
    return _run(scenario, prepared, [_answer("benign", [explanation])])


@pytest.fixture(scope="module")
def abstain(scenario, prepared):
    return _run(scenario, prepared, [_answer("abstain")])


@pytest.fixture(scope="module")
def deterministic(scenario, prepared):
    return _run(scenario, prepared, None)


@pytest.fixture(scope="module")
def unusable(scenario, prepared):
    return _run(scenario, prepared, ["invalid JSON"])


@pytest.fixture(scope="module")
def rejected(scenario, prepared):
    """The model cites an id that was never retrieved: the claim is rejected, the run
    is operationally incomplete, and the model's 'malicious' becomes provisional."""
    bad = _explanation("malicious", "Exfiltration happened.", ["deadbeefdeadbeefdead"])
    return _run(scenario, prepared, [_answer("malicious", [bad])])


def _all(request):
    return [request.getfixturevalue(n)[1] for n in
            ("malicious", "benign", "abstain", "deterministic", "unusable", "rejected")]


def _md_section(md: str, heading: str) -> str:
    start = md.index(f"## {heading}")
    end = md.find("\n## ", start + 1)
    return md[start:end if end != -1 else None]


# ======================================================================================
# Verdict mapping
# ======================================================================================


def test_model_malicious_disposition_is_reported_as_malicious_with_verified_citations(malicious) -> None:
    """A complete run's disposition passes through, with the ids that support it."""
    _, report = malicious
    verdict = report.verdict
    assert verdict.disposition == "Malicious" and verdict.complete
    assert verdict.supporting_event_ids == (FAILURE, SUCCESS, SERVICE_CMD)
    assert verdict.verified_event_ids == verdict.supporting_event_ids
    assert verdict.engine == "d1" and verdict.model == "scripted-test-client"
    assert verdict.profile == "operational-v2"
    assert verdict.evidence_gap == "what job.cmd did is not observed"
    assert "1 probe(s) run" in verdict.evidence_basis
    assert "3 of 3 cited event id(s)" in verdict.evidence_basis


def test_benign_and_abstain_dispositions_map_to_their_labels(benign, abstain) -> None:
    assert benign[1].verdict.disposition == "Benign"
    assert abstain[1].verdict.disposition == "Abstain"
    # An abstention with no explanations cites nothing, and says so rather than
    # leaving the reader to wonder whether the list was dropped.
    assert abstain[1].verdict.supporting_event_ids == ()
    assert "none cited by the concluding explanations" in render_markdown(abstain[1])


def test_deterministic_run_has_no_disposition_and_says_why(deterministic) -> None:
    """No model concluded, so there is no disposition to report -- not a silent gap."""
    state, report = deterministic
    assert state.investigation.get("final_disposition") is None
    verdict = report.verdict
    assert verdict.disposition == "Incomplete"
    assert any("deterministic engine does not issue a disposition" in r
               for r in verdict.incomplete_reasons)
    assert verdict.model == "none (deterministic engine)"
    assert verdict.supporting_event_ids == ()


def test_deterministic_verdict_comes_from_triage_and_says_so(deterministic) -> None:
    """The deterministic arm is scored on triage's disposition of the seed; its report
    must show that same disposition, attributed to triage, never to a model."""
    state, _ = deterministic
    for triage, label in (("malicious", "Malicious"), ("benign", "Benign"), ("abstain", "Abstain")):
        verdict = build_verdict(state, triage_disposition=triage)
        assert verdict.disposition == label and verdict.incomplete_reasons == ()
        assert verdict.disposition_source == "deterministic triage of the seed findings"


def test_triage_disposition_cannot_stand_in_for_a_model(unusable) -> None:
    """A failed model run stays Incomplete whatever triage would have said."""
    state, _ = unusable
    verdict = build_verdict(state, model="m", triage_disposition="malicious")
    assert verdict.disposition == "Incomplete" and verdict.disposition_source == ""


def test_unusable_model_run_is_incomplete_not_abstain(unusable) -> None:
    """The operational layer scores this as abstain; the report must not read that way."""
    state, report = unusable
    assert state.investigation["final_disposition"] == "abstain"
    assert report.verdict.disposition == "Incomplete"
    assert report.verdict.incomplete_reasons
    assert set(state.investigation["operational"]["reasons"]) <= set(report.verdict.incomplete_reasons)


def test_incomplete_run_shows_the_provisional_disposition_but_cites_nothing(rejected) -> None:
    state, report = rejected
    verdict = report.verdict
    assert verdict.disposition == "Incomplete"
    assert verdict.model_disposition == "malicious"
    assert "claims failed evidence verification" in verdict.incomplete_reasons
    assert verdict.supporting_event_ids == ()
    md = _md_section(render_markdown(report), "Verdict")
    assert "provisional disposition:** malicious (not a verdict" in md
    # The rejected explanation is still shown, marked as rejected and not retrieved.
    [item] = report.reasoning_summary
    assert item.status.startswith("rejected")
    assert item.unverified_ids == ("deadbeefdeadbeefdead",)
    assert "`deadbeefdeadbeefdead` (NOT retrieved)" in render_markdown(report)


def test_verdict_rejects_labels_outside_the_four() -> None:
    with pytest.raises(ValueError, match="verdict must be one of"):
        Verdict(disposition="Likely malicious")


def test_verdict_model_has_no_field_for_a_confidence_score() -> None:
    """There is no verdict confidence in this system; the model must not make room for one."""
    names = {f.name for f in fields(Verdict)}
    assert not {n for n in names if "confidence" in n or "probab" in n or "score" in n}


# ======================================================================================
# Investigation tree and reasoning summary
# ======================================================================================


def test_tree_records_each_probe_with_the_models_reason_and_new_events(malicious) -> None:
    state, report = malicious
    tree = report.investigation_tree
    assert tree.alert_title == report.title
    assert tree.rule_ids == state.case.rule_ids
    assert tree.seed_event_ids == state.case.event_ids
    [step] = tree.steps
    assert (step.kind, step.name, step.reason_source) == ("probe", "user_auth_history", "model")
    assert step.arguments == "user='acct-7085'"
    assert step.reason == "account history distinguishes guessing from a stale password"
    # New means not already in the seed: nothing the case started with is re-counted.
    assert step.new_event_ids and not set(step.new_event_ids) & set(state.case.event_ids)
    assert step.new_event_count == state.investigation["rounds"][0]["new_evidence_ids_returned"]


def test_deterministic_tree_shows_the_specialist_trace(deterministic) -> None:
    state, report = deterministic
    steps = report.investigation_tree.steps
    assert [s.name for s in steps] == [r.agent for r in state.results]
    assert all(s.kind == "specialist" and s.reason_source == "deterministic" for s in steps)
    assert steps[0].tools and steps[0].reason == state.results[0].ran_because


def test_reasoning_summary_quotes_the_concluding_round_verbatim(malicious) -> None:
    state, report = malicious
    [item] = report.reasoning_summary
    assert item.statement == MALICIOUS["statement"]
    assert item.label == "malicious" and item.status == "accepted"
    assert item.verified_ids == item.evidence_ids
    md = _md_section(render_markdown(report), "Reasoning Summary")
    assert MODEL_TEXT_NOTE in md
    assert f'Model wrote: "{MALICIOUS["statement"]}"' in md


def test_title_comes_from_the_case_findings(malicious) -> None:
    state, report = malicious
    assert report.title.startswith("Failed logon burst followed by successful authentication")
    assert "(+1 related finding)" in report.title
    assert render_markdown(report).startswith(f"# Incident: {report.title}\n")


# ======================================================================================
# Markdown
# ======================================================================================


def test_markdown_puts_verdict_tree_and_reasoning_before_the_existing_sections(request) -> None:
    for report in _all(request):
        md = render_markdown(report)
        order = [md.index(h) for h in ("## Verdict", "## Investigation Tree",
                                       "## Reasoning Summary", "## Executive Summary",
                                       "## Findings", "## Investigation Trace")]
        assert order == sorted(order)
        tree = _md_section(md, "Investigation Tree")
        assert "Initial alert:" in tree and "ATH investigation" in tree
        assert f"Verdict: {report.verdict.disposition}" in tree


def test_deterministic_markdown_renders_without_rounds(deterministic) -> None:
    _, report = deterministic
    md = render_markdown(report)
    assert report.reasoning_summary == ()
    assert no_reasoning_note("deterministic") in md
    assert "├── endpoint" in md and "why: deterministic priority order" in md


def test_no_probability_or_percentage_in_any_verdict_section(request) -> None:
    """Counts are allowed; a percentage, decimal or 'N% likely' is a score we do not have."""
    for report in _all(request):
        section = _md_section(render_markdown(report), "Verdict")
        html_section = render_html(report).split('id="verdict"', 1)[1].split("</section>", 1)[0]
        for text in (section, html_section):
            assert "%" not in text
            assert not re.search(r"\d\.\d", text)
            assert not re.search(r"(?i)(probability|likelihood|confidence)\s*[:=]?\s*\d", text)
        assert NO_CONFIDENCE_NOTE in section


def test_generated_prose_passes_the_calibration_lint(request) -> None:
    """Every sentence this module writes (not the model's) is checked like a non-FACT
    claim: templated verdict prose must never carry certainty language."""
    prose = [NO_CONFIDENCE_NOTE, MODEL_TEXT_NOTE,
             *(no_reasoning_note(e) for e in ("deterministic", "d1", "orchestrator"))]
    for report in _all(request):
        verdict = report.verdict
        prose += [verdict.evidence_basis, *verdict.incomplete_reasons]
        prose += [s.reason for s in report.investigation_tree.steps if s.reason_source != "model"]
        prose += [item.status for item in report.reasoning_summary]
    claims = [Claim(claim_type=ClaimType.HYPOTHESIS, statement=p, source="llm") for p in prose if p]
    assert audit_calibration(claims) == {}


def test_report_json_keeps_existing_fields_and_adds_the_new_ones(malicious) -> None:
    _, report = malicious
    payload = json.loads(json.dumps(report.to_dict()))
    for existing in ("case_id", "status", "executive_summary", "facts", "limitations",
                     "investigation_path", "evidence_appendix", "data_sources"):
        assert existing in payload
    assert payload["verdict"]["disposition"] == "Malicious"
    assert payload["investigation_tree"]["steps"][0]["name"] == "user_auth_history"
    assert payload["reasoning_summary"][0]["status"] == "accepted"
    assert payload["title"] == report.title


# ======================================================================================
# HTML: self-contained, and every untrusted string escaped
# ======================================================================================


def _poisoned(report):
    """The report with attacker text in a command line, a model explanation, a probe
    reason and the evidence gap -- the four routes untrusted strings take to the page."""
    entry = report.evidence_appendix[0]
    appendix = (replace(entry, summary=f"process cmd.exe cmd '{PAYLOAD}'"),) + report.evidence_appendix[1:]
    step = InvestigationStep(kind="probe", name="process_tree", arguments=f"cmd={PAYLOAD!r}",
                             reason=PAYLOAD, reason_source="model")
    tree = replace(report.investigation_tree, steps=(step,))
    explanation = ModelExplanation(label=PAYLOAD, statement=f"benign {PAYLOAD}",
                                   evidence_ids=(PAYLOAD,), status="accepted")
    verdict = replace(report.verdict, evidence_gap=PAYLOAD)
    assert isinstance(entry, EvidenceAppendixEntry)
    return replace(report, evidence_appendix=appendix, investigation_tree=tree,
                   reasoning_summary=(explanation,), verdict=verdict)


def test_html_escapes_command_lines_and_model_output(malicious) -> None:
    page = render_html(_poisoned(malicious[1]))
    assert "<script" not in page.lower()
    assert '" onmouseover=' not in page
    assert not re.search(r"<[^>]*\son\w+\s*=", page)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;&quot; onmouseover=&quot;alert(2)" in page
    # Every route was rendered -- escaping did not work by dropping the content.
    assert page.count("&lt;script&gt;") >= 5


def test_html_is_self_contained_and_themed(deterministic, malicious) -> None:
    for report in (deterministic[1], malicious[1]):
        page = render_html(report)
        assert page.startswith("<!DOCTYPE html>")
        assert "prefers-color-scheme: dark" in page and 'name="viewport"' in page
        assert not re.search(r"(?i)<(script|link|img|iframe)\b|javascript:|src=|@import|url\(", page)
        for heading in ("Verdict", "Investigation Tree", "Reasoning Summary", "Findings",
                        "Evidence Appendix"):
            assert f"<h2>{heading}</h2>" in page


def test_index_escapes_entries_and_links_only_safe_targets(malicious, deterministic) -> None:
    entries = [
        IndexEntry.from_report(malicious[1], "sample-01_d1.html", expected="malicious"),
        IndexEntry.from_report(deterministic[1], "javascript:alert(1)", label=PAYLOAD),
    ]
    page = render_index(entries)
    assert '<a href="sample-01_d1.html">' in page
    assert 'href="javascript' not in page
    assert "<script" not in page.lower() and '" onmouseover=' not in page
    assert "Expected (scoring only)" in page and "malicious" in page
    assert "1 with a complete verdict" in page
