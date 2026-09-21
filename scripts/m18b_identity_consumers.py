"""M18b-2 measurement: what changed for the consumers of process identity.

The question this answers
--------------------------
M18b-1 put an instance identity on every process and network row and measured it: on
COMISET, ``process.process_guid`` is 100% populated, 94.8% of the ``(device, pid)`` keys
network rows used covered more than one process instance, and the worst one covered 27.
Nothing consumed it. The correlator keyed process lineage on ``(device, parent_pid)``,
``process_tree`` resolved a pid with ``iloc[0]``, and the endpoint specialist published
the result as a FACT.

So this script asks, per corpus, four separate questions, kept separate because pooling
them is how a change like this comes to be reported as an improvement it did not make:

1. **Did detection move?** Findings, by rule, before and after. The answer must be "no"
   everywhere: this milestone touched no detection logic. A corpus where findings moved
   is a defect, not a result.
2. **Did correlation move, and which way?** Cases and links by signal, before and after,
   plus how many of the links after rest on a PID slot rather than on an identity. Links
   *lost* on a process signal are the false attributions the old key could not see;
   links *gained* are relations the old key was too coarse to find.
3. **What does the lineage tool now say about an ambiguous pid?** For every reused
   ``(device, pid)`` key, what the old walk returned (one instance, picked by file
   order, with its ancestors) against what the new one returns (candidates, or an exact
   chain).
4. **What does the investigation say?** The deterministic (NullLLM) arm's claim counts,
   and how many of its FACTs now carry ``inferred from pid`` -- which is the number that
   says how much of this pipeline's process reasoning was resting on a slot all along.

How "before" is obtained
-------------------------
Two ways, and they are checked against each other.

*Frozen.* ``reports/m18b/identity_consumers/BEFORE_7e68840.json`` was produced by running
the pipeline at commit 7e68840 -- the last commit before this milestone -- and is read
here rather than re-derived. It is the only source for the *investigation* numbers,
because reproducing the old specialist's prose would mean transcribing it.

*Recomputed.* :class:`_LegacyProcessIndex` and :func:`legacy_process_tree` are
transcriptions of the two consumers at that commit, and the script runs the **current**
correlator against the legacy index. That reproduces the old links without a checkout,
and every run reports whether it agrees with the frozen file (``agrees_with_frozen``). A
transcription that silently drifted from what it claims to reproduce would make every
"before" number here a fiction, so it is checked rather than trusted.

Usage::

    python scripts/m18b_identity_consumers.py synthetic
    python scripts/m18b_identity_consumers.py comiset
    python scripts/m18b_identity_consumers.py flaws_cloud
    python scripts/m18b_identity_consumers.py attack_data_aws
    python scripts/m18b_identity_consumers.py k8s_ci
    python scripts/m18b_identity_consumers.py k8ntext
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from ath.correlation import correlate_with_stats  # noqa: E402
from ath.correlation import correlator as correlator_module  # noqa: E402
from ath.environment import build_environment_model  # noqa: E402
from ath.hunting import HuntConfig, run_hunt  # noqa: E402
from ath.instance_identity import INFERRED_FROM_PID  # noqa: E402
from ath.schema import (  # noqa: E402
    EVENT_CONTROL,
    EVENT_LOGON,
    EVENT_NETWORK,
    EVENT_PROCESS,
)
from ath.telemetry.loader import Telemetry  # noqa: E402
from ath.triage import assess_findings, set_aside_ids  # noqa: E402
from m18_cloud_detection import load_corpus as _cloud_corpus  # noqa: E402
from pre_schema_parquet import read_canonical_table  # noqa: E402

OUT_DIR = ROOT / "reports" / "m18b" / "identity_consumers"
FROZEN_BEFORE = OUT_DIR / "BEFORE_7e68840.json"

CORPORA = (
    "synthetic", "comiset", "flaws_cloud", "attack_data_aws", "k8s_ci", "k8ntext",
)

# The keys M18b-1 measured as the worst cross-channel attributions on COMISET: one
# host's pid 5924 was held by 27 process instances, pid 548 by three.
COMISET_STUDY_KEYS = (("desktop-4pvps6e", 548), ("desktop-4pvps6e", 5924))

# Only these signals can rest on a process join; the rest cannot be "inferred from pid"
# because they involve no process at all.
PROCESS_SIGNALS = ("same_process", "process_lineage", "sibling_lineage")


# --------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------


def load(corpus: str) -> tuple[Telemetry, dict[str, Any]]:
    """One corpus, through the same adapters the CLI uses and no others.

    COMISET is read from ``reports/m18b/canonical`` and **not** from
    ``reports/m17/canonical``: the M17 freeze predates the identity columns, so reading
    it here would measure this milestone against a corpus that cannot exercise it and
    report the resulting silence as a finding.
    """
    started = time.time()
    if corpus == "comiset":
        directory = ROOT / "reports" / "m18b" / "canonical"
        telemetry = Telemetry(
            processes=read_canonical_table(directory, "comiset", "process", EVENT_PROCESS),
            network=read_canonical_table(directory, "comiset", "network", EVENT_NETWORK),
            logons=read_canonical_table(directory, "comiset", "logon", EVENT_LOGON),
            controls=read_canonical_table(directory, "comiset", "control", EVENT_CONTROL),
        )
        detail = {"path": "reports/m18b/canonical", "adapter": "frozen canonical parquet"}
    else:
        telemetry = _cloud_corpus(corpus)
        detail = {"loader": "scripts/m18_cloud_detection.load_corpus"}
    detail["load_seconds"] = round(time.time() - started, 1)
    detail["rows"] = {
        "process": int(len(telemetry.processes)),
        "network": int(len(telemetry.network)),
        "logon": int(len(telemetry.logons)),
        "control": int(len(telemetry.controls)),
    }
    return telemetry, detail


# --------------------------------------------------------------------------------------
# The two consumers as they were at 7e68840
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _LegacyKey:
    """``(device, pid)`` presented through the interface the current scorer expects.

    Transcribed from the correlator at 7e68840, whose index was::

        self.pid_of[row.event_id] = (row.device, int(row.process_id))
        self.parent_of[row.event_id] = (row.device, int(row.parent_process_id))

    and whose signals were set-intersections over those pairs. ``joins`` therefore
    reports equality and *never* reports a fallback, which is precisely what the old
    output could not say: every link it made was presented as an observation.
    """

    device: str
    process_id: int

    def joins(self, other: _LegacyKey) -> tuple[bool, bool]:
        return self == other, False


class _LegacyProcessIndex:
    """The pre-M18b-2 ``_ProcessIndex``, with the current method names."""

    def __init__(self, telemetry: Telemetry) -> None:
        self._key_of: dict[str, _LegacyKey] = {}
        self._parent_of: dict[str, _LegacyKey] = {}
        self._children: dict[_LegacyKey, set[int]] = {}
        self._spawned_at: dict[_LegacyKey, list[Any]] = {}

        for row in telemetry.processes.itertuples(index=False):
            if pd.notna(row.process_id):
                self._key_of[row.event_id] = _LegacyKey(row.device, int(row.process_id))
            if pd.notna(row.parent_process_id):
                parent = _LegacyKey(row.device, int(row.parent_process_id))
                self._parent_of[row.event_id] = parent
                if pd.notna(row.process_id):
                    self._children.setdefault(parent, set()).add(int(row.process_id))
                self._spawned_at.setdefault(parent, []).append(row.timestamp)

        for row in telemetry.network.itertuples(index=False):
            if pd.notna(row.process_id):
                self._key_of[row.event_id] = _LegacyKey(row.device, int(row.process_id))

    def keys(self, finding) -> set[_LegacyKey]:
        return {self._key_of[e] for e in finding.event_ids if e in self._key_of}

    def parent_keys(self, finding) -> set[_LegacyKey]:
        return {self._parent_of[e] for e in finding.event_ids if e in self._parent_of}

    def fan_out(self, parent: _LegacyKey) -> int:
        return len(self._children.get(parent, ()))

    def spawn_span(self, parent: _LegacyKey) -> timedelta:
        times = self._spawned_at.get(parent)
        return (max(times) - min(times)) if times else timedelta(0)

    def session_parents(self, finding, config) -> set[_LegacyKey]:
        return {
            parent for parent in self.parent_keys(finding)
            if self.fan_out(parent) <= config.max_session_fan_out
            and self.spawn_span(parent) <= config.max_session_span
        }


@contextmanager
def legacy_correlator():
    """Run the current correlator over the legacy index.

    The gating, scoring and case assembly are the current code -- only the *key* is the
    old one, which is the single thing this milestone changed. Swapping the whole
    correlator instead would also swap in every unrelated change since, and the
    difference would stop being attributable.
    """
    original = correlator_module._ProcessIndex
    correlator_module._ProcessIndex = _LegacyProcessIndex
    try:
        yield
    finally:
        correlator_module._ProcessIndex = original


def legacy_process_tree(
    telemetry: Telemetry, device: str, pid: int, depth: int = 3
) -> dict[str, Any]:
    """``ToolBox.process_tree`` as it was at 7e68840, verbatim in behaviour.

    The line this exists to show is ``row = match.iloc[0]``: the first row in file order,
    with no record anywhere in the result that there had been others.
    """
    procs = telemetry.processes
    host = procs[procs["device"] == device]
    chain: list[dict[str, Any]] = []
    current = pid
    for _ in range(depth):
        match = host[host["process_id"] == current]
        if match.empty:
            break
        row = match.iloc[0]
        chain.append({
            "event_id": row["event_id"],
            "timestamp": str(row["timestamp"]),
            "process_name": row["process_name"],
            "process_id": int(row["process_id"]),
            "parent_process_name": row["parent_process_name"],
            "parent_process_id": (
                None if pd.isna(row["parent_process_id"]) else int(row["parent_process_id"])
            ),
        })
        if pd.isna(row["parent_process_id"]):
            break
        current = int(row["parent_process_id"])
    children = host[host["parent_process_id"] == pid]
    return {
        "ancestry": chain,
        "children": int(len(children)),
        "candidates_ignored": int(len(host[host["process_id"] == pid])) - 1,
    }


# --------------------------------------------------------------------------------------
# The pipeline, twice
# --------------------------------------------------------------------------------------


def hunt(telemetry: Telemetry) -> tuple[list, set[str]]:
    """Detection and triage, run once.

    Once, not once per key: neither reads the correlator, so hunting twice in one
    process could only ever produce the same findings twice and would dress a tautology
    up as a measurement. The claim "detection did not move" is checked where it can
    actually fail -- against the findings recorded at 7e68840 in the frozen artifact.
    """
    result = run_hunt(telemetry, config=HuntConfig())
    environment = build_environment_model(telemetry)
    return result.findings, set_aside_ids(assess_findings(result.findings, environment))


def run(telemetry: Telemetry, findings, aside, *, legacy: bool) -> dict[str, Any]:
    """Correlate one corpus under one of the two keys."""
    if legacy:
        with legacy_correlator():
            cases, stats = correlate_with_stats(findings, telemetry, set_aside=aside)
    else:
        cases, stats = correlate_with_stats(findings, telemetry, set_aside=aside)

    links: dict[str, dict[str, Any]] = {}
    for case in cases:
        for link in case.links:
            links[f"{link.left_id}->{link.right_id}"] = {
                "signals": [s.split("(")[0] for s in link.signals],
                "inferred": [s.split("(")[0] for s in link.signals if INFERRED_FROM_PID in s],
                "score": link.score,
            }
    return {
        "findings": len(findings),
        "by_rule": dict(sorted(Counter(f.rule_id for f in findings).items())),
        "cases": len(cases),
        "case_sizes": sorted((len(c.findings) for c in cases), reverse=True)[:10],
        "links_in_cases": sum(len(c.links) for c in cases),
        "links_by_signal": _by_signal(links),
        "run": stats.to_dict(),
        "_links": links,
        "_findings": findings,
        "_cases": cases,
    }


def _by_signal(links: dict[str, dict[str, Any]]) -> dict[str, int]:
    counted: Counter = Counter()
    for link in links.values():
        counted.update(link["signals"])
    return dict(sorted(counted.items()))


def compare(
    before: dict[str, Any], after: dict[str, Any], frozen: dict[str, Any]
) -> dict[str, Any]:
    """What moved between the two keys, at the level of individual links.

    ``lost_process_links`` is the headline: a process signal the old key asserted and
    the identity refuses is an attribution that crossed two instances of one PID slot.
    ``gained_process_links`` is the other direction and is not a regression -- pooled
    per slot, a parent's fan-out and spawn span are those of every run of it at once, so
    the old key could hide a genuine session inside a launcher's totals.
    """
    lost: list[dict[str, Any]] = []
    gained: list[dict[str, Any]] = []
    for pair, old in before["_links"].items():
        new = after["_links"].get(pair, {"signals": []})
        for signal in PROCESS_SIGNALS:
            if signal in old["signals"] and signal not in new["signals"]:
                lost.append({"pair": pair, "signal": signal})
    for pair, new in after["_links"].items():
        old = before["_links"].get(pair, {"signals": []})
        for signal in PROCESS_SIGNALS:
            if signal in new["signals"] and signal not in old["signals"]:
                gained.append({"pair": pair, "signal": signal})
    return {
        # Against the run recorded at 7e68840, which is the only comparison that can
        # fail: this milestone changed no detection logic, so a corpus where findings
        # moved is a defect and not a result.
        "findings_unchanged": (
            frozen.get("findings") == after["findings"]
            and frozen.get("by_rule") == after["by_rule"]
        ) if frozen else None,
        "cases_before": before["cases"], "cases_after": after["cases"],
        "links_before": before["links_in_cases"], "links_after": after["links_in_cases"],
        "links_by_signal_before": before["links_by_signal"],
        "links_by_signal_after": after["links_by_signal"],
        # A process attribution the old key made and the identity refuses: the two sides
        # were two different runs of one PID. This is the false-lineage count.
        "lost_process_links": lost,
        "lost_process_link_count": len(lost),
        "gained_process_links": gained,
        "gained_process_link_count": len(gained),
        "inferred_links_after": after["run"]["inferred_links_by_signal"],
    }


# --------------------------------------------------------------------------------------
# Ambiguity, and what the lineage tool does with it
# --------------------------------------------------------------------------------------


def reused_keys(telemetry: Telemetry, limit: int = 25) -> dict[str, Any]:
    """Every ``(device, pid)`` slot more than one process instance passed through."""
    procs = telemetry.processes
    if procs.empty:
        return {"process_keys": 0, "reused": 0, "worst": None, "keys": []}
    grouped = procs.groupby(["device", "process_id"])["process_guid"].nunique()
    reused = grouped[grouped > 1].sort_values(ascending=False)
    return {
        "process_keys": int(len(grouped)),
        "reused": int(len(reused)),
        "worst": (
            {"key": f"{reused.index[0][0]}|{int(reused.index[0][1])}",
             "instances": int(reused.iloc[0])}
            if len(reused) else None
        ),
        "keys": [
            {"device": device, "pid": int(pid), "instances": int(count)}
            for (device, pid), count in list(reused.items())[:limit]
        ],
    }


def tree_study(
    telemetry: Telemetry, tools, keys: list[tuple[str, int]]
) -> list[dict[str, Any]]:
    """For each slot: what the old walk returned, and what the new one returns."""
    study: list[dict[str, Any]] = []
    procs = telemetry.processes
    for device, pid in keys:
        rows = procs[(procs["device"] == device) & (procs["process_id"] == pid)]
        before = legacy_process_tree(telemetry, device, pid)
        after = tools.process_tree(device, pid, agent="measurement")
        study.append({
            "key": f"{device}|{pid}",
            "process_rows": int(len(rows)),
            "distinct_identities": int(rows["process_guid"].nunique()),
            "instances": [
                {"process_name": r["process_name"], "timestamp": str(r["timestamp"]),
                 "process_guid": r["process_guid"]}
                for r in rows.sort_values("timestamp").to_dict("records")[:5]
            ],
            "before": {
                "picked": before["ancestry"][0]["process_name"] if before["ancestry"] else None,
                "ancestry": [a["process_name"] for a in before["ancestry"]],
                "children": before["children"],
                "other_instances_silently_discarded": before["candidates_ignored"],
            },
            "after": {
                "resolution": after["resolution"],
                "ambiguous_pid": after["ambiguous_pid"],
                "candidates": [
                    {"process_name": c["process_name"], "timestamp": c["timestamp"],
                     "process_guid": c["process_guid"]}
                    for c in after["candidates"][:5]
                ],
                "ancestry": [
                    {"process_name": a["process_name"], "resolved_by": a["resolved_by"]}
                    for a in after["ancestry"]
                ],
                "children": len(after["children"]),
                "notes": after["notes"],
            },
        })
    return study


# --------------------------------------------------------------------------------------
# The deterministic investigation
# --------------------------------------------------------------------------------------


def investigate(telemetry: Telemetry, findings, cases, limit: int) -> dict[str, Any]:
    """The NullLLM arm over this corpus's cases, counting what the claims now admit.

    No model is called and nothing is tuned. What is new here is
    ``facts_labelled_inferred_from_pid``: FACTs whose process attribution rests on a PID
    slot. Those sentences were published before this milestone too -- without the clause.
    """
    from ath.agent.claims import ClaimVerifier  # noqa: PLC0415
    from ath.agent.llm import NullLLM  # noqa: PLC0415
    from ath.agent.orchestrator import (  # noqa: PLC0415
        InvestigationConfig,
        InvestigationOrchestrator,
    )
    from ath.agent.tools import ToolBox  # noqa: PLC0415
    from ath.environment import build_environment_model as _env  # noqa: PLC0415

    if not cases:
        return {"cases": 0}
    tools = ToolBox(telemetry, findings, cases)
    orchestrator = InvestigationOrchestrator(
        tools, ClaimVerifier(telemetry), llm=NullLLM(),
        config=InvestigationConfig(use_llm_planner=False, use_llm_synthesis=False),
        environment=_env(telemetry),
    )
    totals: Counter = Counter()
    labelled: list[str] = []
    ambiguity: list[str] = []
    for case in cases[:limit]:
        state = orchestrator.investigate(case)
        payload = state.to_dict()
        counts = payload["counts"]
        totals["cases"] += 1
        for key in ("facts", "inferences", "hypotheses", "rejected", "tool_calls"):
            totals[key] += counts[key]
        totals["steps"] += payload["steps"]
        for claim in payload["claims"]:
            statement = str(claim.get("statement", ""))
            if INFERRED_FROM_PID in statement:
                if claim.get("type") == "FACT":
                    labelled.append(statement)
                else:
                    ambiguity.append(statement)
            if "different process instances" in statement:
                ambiguity.append(statement)
    return {
        "totals": dict(totals),
        "facts_labelled_inferred_from_pid": len(labelled),
        "claims_naming_an_ambiguous_pid": len(dict.fromkeys(ambiguity)),
        "examples": [s[:300] for s in (labelled + ambiguity)[:6]],
    }


# --------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("corpus", choices=CORPORA)
    parser.add_argument("--investigate", type=int, default=10,
                        help="how many cases the deterministic arm runs (0 to skip).")
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = parser.parse_args()

    telemetry, source = load(args.corpus)
    print(f"{args.corpus}: {source['rows']}", flush=True)

    findings, aside = hunt(telemetry)
    before = run(telemetry, findings, aside, legacy=True)
    after = run(telemetry, findings, aside, legacy=False)

    frozen = (
        json.loads(FROZEN_BEFORE.read_text(encoding="utf-8"))
        if FROZEN_BEFORE.exists() else {}
    )
    frozen_corpus = frozen.get(args.corpus, {})
    movement = compare(before, after, frozen_corpus)
    agreement = {
        "frozen_artifact": str(FROZEN_BEFORE.relative_to(ROOT)).replace("\\", "/"),
        "findings": frozen_corpus.get("findings"),
        "cases": frozen_corpus.get("cases"),
        "links": frozen_corpus.get("links"),
        "agrees_with_frozen": (
            frozen_corpus.get("findings") == before["findings"]
            and frozen_corpus.get("cases") == before["cases"]
            and frozen_corpus.get("links") == before["links_in_cases"]
            and frozen_corpus.get("links_by_signal") == before["links_by_signal"]
        ) if frozen_corpus else None,
    }

    from ath.agent.tools import ToolBox  # noqa: PLC0415

    ambiguity = reused_keys(telemetry)
    if args.corpus == "comiset":
        study_keys = list(COMISET_STUDY_KEYS)
    else:
        study_keys = [(k["device"], k["pid"]) for k in ambiguity["keys"][:5]]
    tools = ToolBox(telemetry, after["_findings"], after["_cases"])
    study = tree_study(telemetry, tools, study_keys)

    record: dict[str, Any] = {
        "corpus": args.corpus,
        "source": source,
        "before_from": agreement,
        "detection": {
            "findings_at_7e68840": frozen_corpus.get("findings"),
            "findings_after": after["findings"],
            "by_rule_at_7e68840": frozen_corpus.get("by_rule"),
            "by_rule_after": after["by_rule"],
            "unchanged": movement["findings_unchanged"],
        },
        "correlation": movement,
        "run_stats_after": after["run"],
        "pid_ambiguity": ambiguity,
        "process_tree_study": study,
    }
    if args.investigate:
        record["investigation_after"] = investigate(
            telemetry, after["_findings"], after["_cases"], args.investigate,
        )
        record["investigation_before"] = frozen.get(
            f"{args.corpus}_investigation_before", {}
        )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"{args.corpus}.json"
    out.write_text(json.dumps(record, indent=1, default=str), encoding="utf-8")
    print(
        f"findings {before['findings']} -> {after['findings']} | "
        f"cases {before['cases']} -> {after['cases']} | "
        f"links {before['links_in_cases']} -> {after['links_in_cases']} | "
        f"lost {movement['lost_process_link_count']} gained "
        f"{movement['gained_process_link_count']} | wrote {out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
