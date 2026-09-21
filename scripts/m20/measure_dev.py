"""M20 measurement: the development-split numbers section 5's pre-registration needs.

What this computes and why each number exists
-----------------------------------------------
Section 5 requires that "every number is derived from the development split and stated as
a rate, so the holdout's different length does not excuse a miss". Each block below
exists because one clause of section 5 or of its decision rule needs it:

* **findings/day by rule** -- the template's first block, and prediction 1's +/- 50% band.
* **dispositions** -- prediction 2's "benign disposition fraction".
* **severity mix** -- predictions 3 and 4 (zero CRITICAL; HIGH only from the two named
  exceptions), including AWS-004-at-HIGH per day, which prediction 4 names explicitly.
* **per-rule share of all findings** -- prediction 5's "no single rule contributes > __ %".
* **findings per analyst-hour** -- the decision rule's last clause, "fewer than one per
  analyst-hour at the 8 h/day staffing the corpus assumes -- i.e. < 40 findings over
  5 days". Analyst-hours are therefore ``days x 8``, and the figure is computed from
  *total* findings, not post-triage ones, because that is what the clause counts.
* **per actor** -- not in the template, but it is the number that says whether a rate is
  a property of the account or of one synthetic identity, which is exactly the limitation
  section 6 admits to.

The denominator
----------------
"Per day" is per **distinct UTC date present in the telemetry**, not per elapsed 24 h and
not the plan's nominal 9. If a day's deliveries are missing, dividing by 9 would quietly
report a lower rate than was observed; dividing by the days actually present reports the
rate of the data in hand and says how many days that was.

Why the hunt runs twice
------------------------
``profile_telemetry`` returns aggregates, not the findings, and the per-day / per-actor /
per-severity-per-rule breakdown needs the findings themselves. So the profile is taken
first and ``run_hunt`` is called once more for the detail. Both are deterministic over
the same telemetry, and :func:`measure` asserts the two agree on findings-by-rule -- a
disagreement would mean the profile and the breakdown were describing different runs,
which is the kind of silent divergence this project treats as a defect.

Sealing (INV-4)
----------------
The default path is the development split. A path naming the holdout is refused unless
``reports/m20/PREREGISTERED.md`` exists **and contains no unfilled blanks** -- see
``m20.common.holdout_gate``. Committing the template with its ``__`` still in it does not
open the gate.

Usage::

    python scripts/m20/measure_dev.py --telemetry-dir data/external/m20_benign_cloud/dev \
        --out reports/m20/dev_measurements.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from m20.common import (  # noqa: E402
    DEFAULT_PREREGISTRATION,
    holdout_gate,
    load_cloudtrail,
    mentions_holdout,
)

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_OUT = ROOT / "reports" / "m20" / "dev_measurements.json"
TOOL = "measure_dev.py"

#: The seven rules section 1 of the plan puts under test, in the plan's order. Listed
#: explicitly so a rule that fired zero times is reported as zero rather than omitted --
#: AWS-002's zero is a prediction (section 2), and a missing key would read as "not
#: measured".
RULES_UNDER_TEST = (
    "ATH-005", "AWS-001", "AWS-002", "AWS-003", "AWS-004", "AWS-005", "AWS-006",
)

ANALYST_HOURS_PER_DAY = 8  # section 5's decision rule: "the 8 h/day staffing"


def measure(telemetry_dir: Path, preregistration: Path = DEFAULT_PREREGISTRATION) -> dict:
    """Every number section 5 needs, over one split.

    Raises:
        SystemExit: if ``telemetry_dir`` names the holdout and the pre-registration is
            missing or incomplete (INV-4).
    """
    holdout_gate(telemetry_dir, preregistration, TOOL)

    from ath.environment import build_environment_model
    from ath.evaluation.profile import profile_telemetry
    from ath.hunting import HuntConfig, run_hunt
    from ath.triage import assess_findings

    telemetry, result = load_cloudtrail(telemetry_dir)
    profile = profile_telemetry(telemetry)

    hunt = run_hunt(telemetry, config=HuntConfig())
    findings = hunt.findings
    by_rule = Counter(f.rule_id for f in findings)
    if dict(by_rule) != dict(profile.findings_by_rule):
        raise SystemExit(
            "profile_telemetry and run_hunt disagree on findings by rule "
            f"(profile {dict(profile.findings_by_rule)} vs hunt {dict(by_rule)}). The measurement would be describing two "
            "different runs."
        )

    environment = build_environment_model(telemetry)
    assessments = assess_findings(findings, environment)
    dispositions = Counter(a.disposition.value for a in assessments.values())

    days = sorted({f.first_seen.date().isoformat() for f in findings})
    event_days = _event_days(telemetry)
    denominator = len(event_days) or 1

    per_rule = {}
    for rule_id in sorted(set(RULES_UNDER_TEST) | set(by_rule)):
        rule_findings = [f for f in findings if f.rule_id == rule_id]
        severities = Counter(f.severity.value for f in rule_findings)
        per_day = Counter(f.first_seen.date().isoformat() for f in rule_findings)
        per_rule[rule_id] = {
            "findings": len(rule_findings),
            "per_day": round(len(rule_findings) / denominator, 4),
            "days_with_a_finding": len(per_day),
            "by_day": dict(sorted(per_day.items())),
            "by_severity": dict(severities),
            "high_per_day": round(severities.get("high", 0) / denominator, 4),
            "share_of_all_findings": (
                round(len(rule_findings) / len(findings), 4) if findings else 0.0
            ),
            "under_test": rule_id in RULES_UNDER_TEST,
        }

    total = len(findings)
    analyst_hours = denominator * ANALYST_HOURS_PER_DAY
    benign = dispositions.get("likely_benign", 0)

    return {
        "_about": (
            "M20 development-split measurement. Feeds section 5's pre-registration; "
            "holdout predictions are made from these numbers and are not adjusted after "
            "the holdout is opened."
        ),
        "telemetry_dir": telemetry_dir.as_posix(),
        "split": "holdout" if mentions_holdout(telemetry_dir) else "dev",
        "import": {
            "rows_read": result.rows_read,
            "events": profile.events,
            "events_by_table": profile.events_by_table,
            "window_hours": round(profile.window_hours, 3),
            "files_rejected": [str(a) for a in result.admitted_files if not a.admitted],
            "normalisation_issues": len(result.issues),
        },
        "days": {
            "event_days": event_days,
            "count": len(event_days),
            "denominator_note": (
                "rates are per distinct UTC date present in the telemetry, not per "
                "nominal plan day"
            ),
            "days_with_findings": days,
        },
        "findings": {
            "total": total,
            "by_rule": dict(by_rule),
            "by_severity": dict(profile.findings_by_severity),
            "after_triage": profile.findings_after_triage,
            "largest_rule_share": max(
                (entry["share_of_all_findings"] for entry in per_rule.values()), default=0.0,
            ),
        },
        "per_rule": per_rule,
        "per_actor": dict(Counter(f.user for f in findings).most_common()),
        "per_actor_by_rule": _per_actor_by_rule(findings),
        "dispositions": dict(dispositions),
        "benign_disposition_fraction": round(benign / total, 4) if total else None,
        "analyst_load": {
            "analyst_hours_per_day": ANALYST_HOURS_PER_DAY,
            "analyst_hours": analyst_hours,
            "findings_per_analyst_hour": round(total / analyst_hours, 4) if analyst_hours else None,
            "meets_under_one_per_analyst_hour": (
                total < analyst_hours if analyst_hours else None
            ),
            "definition": (
                "section 5 decision rule: total findings over the split, divided by "
                "days x 8 h. The clause counts findings, not post-triage findings."
            ),
        },
        "cases": {
            "cases": profile.cases,
            "singleton_cases": profile.singleton_cases,
            "links": profile.links,
        },
        "timings_seconds": {
            "hunt": round(profile.seconds_hunt, 3),
            "environment": round(profile.seconds_environment, 3),
            "triage": round(profile.seconds_triage, 3),
            "correlate": round(profile.seconds_correlate, 3),
        },
    }


def _event_days(telemetry) -> list:
    days = set()
    for frame in (telemetry.controls, telemetry.logons, telemetry.processes, telemetry.network):
        if frame is not None and len(frame):
            days |= set(frame["timestamp"].dt.strftime("%Y-%m-%d"))
    return sorted(days)


def _per_actor_by_rule(findings) -> dict:
    nested = {}
    for finding in findings:
        nested.setdefault(finding.rule_id, Counter())[finding.user] += 1
    return {rule: dict(counter.most_common()) for rule, counter in sorted(nested.items())}


# --------------------------------------------------------------------------------------
# Section 5's template, with the development numbers filled in
# --------------------------------------------------------------------------------------


def render_preregistration(measurements: dict) -> str:
    """Section 5's template, dev numbers filled, every holdout prediction left ``__``.

    The asymmetry is the point. The observation block is measurement and is filled here;
    the prediction block is a commitment and can only be filled by the person making it.
    Leaving the blanks in also means the rendered file does **not** pass
    ``m20.common.holdout_gate`` -- so the document this script prints cannot itself
    unseal the holdout until a human has completed it.
    """
    per_rule = measurements["per_rule"]
    events = measurements["import"]["events"]
    day_count = measurements["days"]["count"]

    def rate(rule_id):
        return "{0:.2f}".format(per_rule.get(rule_id, {}).get("per_day", 0.0))

    lines = [
        f"Development-split observation (days 1-9, N events = {events}):",
        "  findings/day by rule:  ATH-005 {0}  AWS-001 {1}  AWS-002 {2}".format(
            rate("ATH-005"), rate("AWS-001"), rate("AWS-002")),
        "                         AWS-003 {0}  AWS-004 {1}  AWS-005 {2}  AWS-006 {3}".format(
            rate("AWS-003"), rate("AWS-004"), rate("AWS-005"), rate("AWS-006")),
        "",
        "Predictions for the sealed holdout (days 10-14):",
        "  1. findings/day per rule, +/- band: as above, +/- 50%",
        "  2. triage benign disposition fraction: >= __ % of findings are dispositioned",
        "     benign by ATH's triage",
        "  3. CRITICAL findings: exactly 0. Named exception: none -- AWS-002 is never",
        "     exercised (section 2), so any CRITICAL is a defect.",
        "  4. HIGH findings: exactly 0, with two named exceptions --",
        "     AWS-004 at HIGH from W10 (>=5 resource types denied), expected __ /day;",
        "     ATH-005 at HIGH only if a further lockout occurs, expected 0.",
        "  5. persistent high-severity noise: no single rule contributes > __ % of all",
        "     findings across the holdout.",
        "",
        "-- measured on the development split, for the person filling the blanks above --",
        "  days measured: {0} ({1})".format(
            day_count, ", ".join(measurements["days"]["event_days"]) or "none"),
        "  total findings: {0}; after triage: {1}".format(
            measurements["findings"]["total"], measurements["findings"]["after_triage"]),
        "  severity mix: {0}".format(measurements["findings"]["by_severity"] or "{}"),
        "  benign disposition fraction: {0}".format(
            measurements["benign_disposition_fraction"]),
        "  AWS-004 at HIGH: {0}/day".format(per_rule.get("AWS-004", {}).get("high_per_day", 0.0)),
        "  largest single-rule share of all findings: {0}".format(
            measurements["findings"]["largest_rule_share"]),
        "  findings per analyst-hour ({0} h/day): {1} -- under one per analyst-hour: {2}".format(
            measurements["analyst_load"]["analyst_hours_per_day"],
            measurements["analyst_load"]["findings_per_analyst_hour"],
            measurements["analyst_load"]["meets_under_one_per_analyst_hour"],
        ),
        "",
        "Decision rule for \"operationally acceptable\", fixed before opening: see",
        "docs/m20-benign-cloud-validation-plan.md section 5. The predictions above are",
        "not adjusted after the holdout is opened; a miss on any clause is recorded as a",
        "miss.",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--telemetry-dir", type=Path, required=True,
                        help="the development split; a holdout path needs a filled PREREGISTERED.md")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--preregistration", type=Path, default=DEFAULT_PREREGISTRATION)
    parser.add_argument("--template-out", type=Path, default=None,
                        help="also write the rendered section 5 template here")
    args = parser.parse_args(argv)

    holdout_gate(args.telemetry_dir, args.preregistration, TOOL)
    measurements = measure(args.telemetry_dir, args.preregistration)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(measurements, indent=2) + "\n", encoding="utf-8")

    template = render_preregistration(measurements)
    if args.template_out:
        args.template_out.parent.mkdir(parents=True, exist_ok=True)
        args.template_out.write_text(template, encoding="utf-8")
    print(template)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
