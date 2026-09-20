"""The README's measured claims, checked against the code that measures them.

Why this exists
---------------
The README accumulated stale figures as milestones landed: it said "Eight" rules, "8"
detections, "16 KQL files" and "ten rules" in different places while the registry held
twenty; it said stage coverage was 10/10 after the dataset had grown to 12 labelled
stages; it said "652 tests" when nothing could verify that number. None of that was a
product defect and all of it was a documentation defect that a reader has no way to
tell apart from one.

The rule here is the same as everywhere else in this project: a number in prose is a
claim, and a claim is either derived from the thing it describes or it is not made.
Each test below parses a specific kind of claim out of ``README.md`` and compares it to
the value the code produces on the shipped dataset. A test that finds *no* claim of its
kind fails too, so a rewrite that quietly drops a figure cannot pass by omission.

What is deliberately not checked
--------------------------------
* The **Roadmap** section. It is a ledger of what each milestone delivered *at the
  time*, so "10 detection rules" in the Milestone 2 row is correct history, not a stale
  claim. The section is cut out before any pattern runs.
* Explicitly historical sentences elsewhere ("it was 8/10 before Milestone 6"). The
  patterns are anchored to the present-tense phrasings the README uses for current
  figures, and the historical ones do not match them.
* Numbers measured on external corpora. Those live in ``docs/`` reports that are frozen
  by design, and the corpora are not in the repository to re-measure against.
"""

from __future__ import annotations

import re

import pytest

from ath.config import PROJECT_ROOT, RAW_DATA_DIR
from ath.evaluation import evaluate
from ath.hunting import registered_rule_ids, run_hunt
from ath.telemetry.loader import load_telemetry

README = PROJECT_ROOT / "README.md"

_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "sixteen": 16,
    "twenty": 20,
}


def _number(token: str) -> int:
    token = token.strip().lower().replace(",", "")
    return int(token) if token.isdigit() else _WORDS[token]


def _section(text: str, heading: str) -> str:
    """The body of ``## heading`` up to the next ``## `` heading (or end of file)."""
    match = re.search(rf"^## {re.escape(heading)}\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert match, f"README has no '## {heading}' section"
    return match.group(1)


@pytest.fixture(scope="module")
def readme() -> str:
    return README.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def prose(readme: str) -> str:
    """The README with the Roadmap ledger removed; see the module docstring."""
    roadmap = re.search(r"^## Roadmap\s*$.*?(?=^## |\Z)", readme, re.M | re.S)
    assert roadmap, "README has no Roadmap section"
    return readme[: roadmap.start()] + readme[roadmap.end():]


@pytest.fixture(scope="module")
def telemetry():
    return load_telemetry(RAW_DATA_DIR)


@pytest.fixture(scope="module")
def hunt(telemetry):
    return run_hunt(telemetry)


@pytest.fixture(scope="module")
def report(hunt, telemetry):
    return evaluate(hunt, RAW_DATA_DIR, total_events=telemetry.event_count)


# --------------------------------------------------------------------------------------
# Rule counts
# --------------------------------------------------------------------------------------

_RULE_COUNT_PATTERNS = (
    r"\b(\w+) (?:deterministic |registered )?detection rules\b",
    r"\b(\w+) deterministic rules\b",
    r"\brun all (\w+) detections\b",
    r"\b(\w+) KQL files\b",
    r"\bthis project's (\w+) rules\b",
    r"Rules run\s*:\s*(\d+)",
)


def test_every_prose_rule_count_matches_the_registry(prose: str) -> None:
    """Fails on the next "Eight deterministic rules" written after the ninth rule."""
    expected = len(registered_rule_ids())
    claims = []
    for pattern in _RULE_COUNT_PATTERNS:
        for match in re.finditer(pattern, prose, re.I):
            token = match.group(1)
            if token.lower() not in _WORDS and not token.isdigit():
                continue  # "the detection rules", "these detection rules"
            claims.append((match.group(0), _number(token)))
    assert claims, "README makes no rule-count claim the patterns recognise"
    wrong = [(text, n) for text, n in claims if n != expected]
    assert not wrong, f"rule-count claims disagreeing with the registry ({expected}): {wrong}"


def test_the_detections_table_lists_exactly_the_registered_rules(readme: str) -> None:
    table = _section(readme, "Detections")
    listed = set(re.findall(r"^\| ((?:ATH|AWS|K8S)-\d{3}) \|", table, re.M))
    assert listed == set(registered_rule_ids())


def test_the_mappings_table_covers_every_registered_rule(readme: str) -> None:
    """The mapper maps all twenty; the README's table used to stop at ATH-010."""
    section = _section(readme, "MITRE ATT&CK mapping")
    table = section[section.index("### Mappings implemented"):]
    listed = set(re.findall(r"^\| ((?:ATH|AWS|K8S)-\d{3}) \|", table, re.M))
    assert listed == set(registered_rule_ids())


# --------------------------------------------------------------------------------------
# Measured results on the shipped dataset
# --------------------------------------------------------------------------------------


def test_stage_coverage_claims_match_the_evaluator(prose: str, report) -> None:
    covered = len(report.covered_stages)
    total = covered + len(report.uncovered_stages)
    claims = re.findall(r"[Ss]tage coverage(?: now reads)?:?\s*\**(\d+)/(\d+)", prose)
    assert claims, "README makes no stage-coverage claim"
    wrong = [c for c in claims if (int(c[0]), int(c[1])) != (covered, total)]
    assert not wrong, f"stage-coverage claims disagreeing with {covered}/{total}: {wrong}"


def test_the_hunt_summary_block_matches_a_live_hunt(readme: str, hunt) -> None:
    block = re.search(
        r"\$ python main\.py hunt --summary\n(.*?)```", readme, re.S,
    )
    assert block, "README has no hunt --summary block"
    text = block.group(1)
    rules_run = int(re.search(r"Rules run\s*:\s*(\d+)", text).group(1))
    findings = int(re.search(r"Findings\s*:\s*(\d+)", text).group(1))
    assert rules_run == len(hunt.rules_run)
    assert findings == hunt.finding_count
    severities = dict(re.findall(r"(CRITICAL|HIGH|MEDIUM|LOW)=(\d+)", text))
    actual: dict[str, int] = {}
    for finding in hunt.findings:
        actual[finding.severity.value.upper()] = actual.get(finding.severity.value.upper(), 0) + 1
    assert {k: int(v) for k, v in severities.items()} == actual


def test_the_evaluate_block_matches_a_live_evaluation(readme: str, report) -> None:
    # Two blocks start with this command: the error shown for unlabelled imports, and
    # the real table. The one with an OVERALL line is the table.
    blocks = re.findall(r"\$ python main\.py evaluate\n(.*?)```", readme, re.S)
    overall = None
    for block in blocks:
        overall = re.search(r"^OVERALL\s+(\d+)\s+(\d+)\s+([\d.]+)", block, re.M) or overall
    assert overall, "README has no evaluate block with an OVERALL line"
    assert int(overall.group(1)) == report.total_true_positives
    assert int(overall.group(2)) == report.total_false_positives
    assert float(overall.group(3)) == pytest.approx(report.overall_precision, abs=0.005)
    prose_tp = re.search(r"\*\*(\d+) true positives\*\*", readme)
    assert prose_tp and int(prose_tp.group(1)) == report.total_true_positives


def test_the_dataset_section_matches_the_shipped_tables(readme: str, telemetry) -> None:
    section = _section(readme, "The dataset")
    rows = {name: int(n) for name, n in re.findall(r"^\| (process|network|logon) \| (\d+) \|", section, re.M)}
    assert rows == {
        "process": len(telemetry.processes),
        "network": len(telemetry.network),
        "logon": len(telemetry.logons),
    }
    events = re.search(r"([\d,]+) events over\s+four hours", section)
    assert events and _number(events.group(1)) == telemetry.event_count
    powershell = re.search(r"contains (\d+) PowerShell\s+executions", section)
    actual = int((telemetry.processes["process_name"].str.lower() == "powershell.exe").sum())
    assert powershell and int(powershell.group(1)) == actual


# --------------------------------------------------------------------------------------
# Claims that must not be made at all
# --------------------------------------------------------------------------------------


def test_the_readme_does_not_state_a_test_count(prose: str) -> None:
    """"652 tests" was wrong by a wide margin and nothing in the repository could verify
    it. A count belongs in ``pytest`` output, not in prose that nobody re-runs."""
    claims = re.findall(r"\b\d[\d,]*\s+tests\b", prose)
    assert not claims, f"README states a test count that nothing verifies: {claims}"
