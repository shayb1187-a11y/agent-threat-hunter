"""Paired comparison of two local models run under the same D1 investigator.

Two row sets are comparable only when everything but the model is the same: the manifest
(the cases and their telemetry), the investigator prompts, schema and bounds (recorded on
every row's header), the arm, the repeat and the seed. Both row directories are read
through the same :func:`~ath.experiments.summarise.select_rows` filter the summary uses,
then the comparison refuses -- rather than compares -- when the two sets differ in
anything but the model. A comparison of rows from two prompt versions would be a prompt
experiment mislabelled as a model experiment.

It computes nothing new about a row. Every number is read from what the run recorded.
No significance test: twenty development cases are a model-selection set, not a
benchmark, and the frozen holdout is not read here.

Orderings (what "better" means per dimension; each is a rule, not a judgement):

* ``decision``      correct decision > abstain > wrong decision, against the row's label;
                    unlabelled rows are not ordered.
* ``link_2``        recovered > not, on rows that define one.
* ``new_used``      more new (non-case) evidence ids cited in accepted final claims.
* ``productive``    more probes that returned at least one new id.
* ``rejected``      fewer rejected model claims.
* ``invalid_refs``  fewer cited ids that do not exist.
* ``tokens``        fewer total tokens.
* ``wall``          less wall time.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from ath.evaluation.ablation.local import completed_rows
from ath.experiments.freeze import write_json, write_text
from ath.experiments.manifest_build import head, read_manifest
from ath.experiments.paths import Layout
from ath.experiments.runs import RunRecord
from ath.experiments.summarise import _median, row_summary, select_rows

DIMENSIONS: tuple[str, ...] = (
    "decision", "link_2", "new_used", "productive", "rejected", "invalid_refs", "tokens", "wall",
)
UNCOMPARED_CLIENT_FIELDS = ("base_url", "timeout_seconds_per_attempt", "max_attempts", "backoff_seconds", "provider")


class NotComparable(RuntimeError):
    """The two row sets differ in something other than the model."""


# -- per-row facts --------------------------------------------------------------------------


def row_facts(payload: dict[str, Any], *, manifest_digest: str | None = None, telemetry_hashes: dict[str, str] | None = None) -> dict[str, Any]:
    """One row's comparable facts: the summary's per-row reading plus the probe ledger."""
    summary = row_summary(payload, manifest_digest=manifest_digest, telemetry_hashes=telemetry_hashes)
    row = payload["row"]
    header = payload.get("header") or {}
    state = row.get("state") or {}
    investigation = state.get("investigation") or {}
    rounds = investigation.get("rounds") or []
    probes = [r for r in rounds if r.get("chosen_probe")]
    productive = [r for r in probes if (r.get("new_evidence_ids_returned") or 0) > 0]
    raw_scores = row.get("scores") or {}
    cited = raw_scores.get("cited_event_ids")
    existing = raw_scores.get("cited_event_ids_existing")
    label = summary["verdict_label"]
    disposition = summary["disposition"]
    if label in ("malicious", "benign"):
        decision = "correct" if disposition == label else ("abstain" if disposition == "abstain" else "wrong")
    else:
        decision = None
    links = summary["links"] or {}
    link_2 = next((v for k, v in links.items() if k.endswith("LINK-2")), None)
    link_1 = next((v for k, v in links.items() if k.endswith("LINK-1")), None)
    investigator = summary["investigator"]
    return {
        "key": f"{payload['key']['corpus']}/{payload['key']['case_id']}",
        "model": payload["key"].get("model"),
        "quantization": payload["key"].get("quantization"),
        "model_digest": ((header.get("model") or {}).get("digest") or "")[:12],
        "run_id": summary.get("run_id"),
        "status": summary["status"],
        "completed_strict": summary["completed_strict"],
        "degraded": summary["degraded"],
        "degradation_reason": summary["degradation_reason"],
        "truncated": summary["output_truncated"],
        "unparseable": summary["unparseable_responses"],
        "label": label,
        "disposition": disposition,
        "decision": decision,
        "link_1": link_1,
        "link_2": link_2,
        "links_valid": summary["links_valid"],
        "probes": [(r["chosen_probe"] or {}).get("tool") for r in probes],
        "probes_total": len(probes),
        "productive_probes": len(productive),
        "unproductive_probes": len(probes) - len(productive),
        "new_returned": investigation.get("new_evidence_ids_returned"),
        "new_shown": investigation.get("new_evidence_ids_shown"),
        "new_used": investigation.get("new_evidence_ids_used"),
        "hypothesis_changed_after_tool": investigation.get("hypothesis_changed_after_tool"),
        "benign_alternative_final": investigation.get("benign_hypothesis_present_final"),
        "rejected": summary["scores"]["rejected_claims"],
        "rejection_reasons": dict(raw_scores.get("rejection_reasons") or {}),
        "invalid_refs": (cited - existing) if isinstance(cited, int) and isinstance(existing, int) else None,
        "evidence_correctness": summary["scores"]["evidence_correctness"],
        "unsupported": summary["scores"]["unsupported_claims"],
        "facts": summary["scores"]["facts"], "inferences": summary["scores"]["inferences"], "hypotheses": summary["scores"]["hypotheses"],
        "model_calls": summary["model_calls"],
        "tool_calls": summary["scores"]["tool_calls"],
        "prompt_tokens": investigator["prompt_tokens"],
        "completion_tokens": investigator["completion_tokens"],
        "tokens": summary["tokens"],
        "wall_seconds": summary["wall_seconds"],
        "median_call_seconds": investigator["median_total_seconds"],
        "ram": summary["ram"],
    }


# -- comparability --------------------------------------------------------------------------


def _identity(payload: dict[str, Any]) -> dict[str, Any]:
    header = payload.get("header") or {}
    key = payload["key"]
    return {
        "arm": key.get("arm"), "repeat": key.get("repeat"), "seed": key.get("seed"),
        "manifest_hash": payload["row"].get("manifest_hash"),
        "prompt_version": header.get("prompt_version"),
        "investigator": json.dumps(header.get("investigator") or {}, sort_keys=True),
        "client_configuration": json.dumps(
            {k: v for k, v in (header.get("client_configuration") or {}).items()
             if k not in UNCOMPARED_CLIENT_FIELDS},
            sort_keys=True, default=str,
        ),
    }


def assert_comparable(rows_a: Sequence[dict[str, Any]], rows_b: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The shared identity of two row sets, or :class:`NotComparable` naming what differs.

    ``client_configuration`` compares everything the client sends except where it sends
    it: ``model`` is expected to differ and is reported, not refused; ``num_ctx``,
    ``num_predict_cap``, ``think``, ``format`` and the sampling must be equal, because a
    model given a bigger budget is a different experiment.
    """
    if not rows_a or not rows_b:
        raise NotComparable("one of the row sets is empty; nothing to pair")
    ids_a = {json.dumps(_identity(r), sort_keys=True) for r in rows_a}
    ids_b = {json.dumps(_identity(r), sort_keys=True) for r in rows_b}
    if len(ids_a) != 1 or len(ids_b) != 1:
        raise NotComparable("a row set mixes experiment identities; summarise it first and read rows_excluded")
    a, b = _identity(rows_a[0]), _identity(rows_b[0])
    differences = []
    for field in ("arm", "repeat", "seed", "manifest_hash", "prompt_version", "investigator"):
        if a[field] != b[field]:
            differences.append(f"{field}: {str(a[field])[:40]!r} vs {str(b[field])[:40]!r}")
    conf_a = json.loads(a["client_configuration"])
    conf_b = json.loads(b["client_configuration"])
    for name in sorted(set(conf_a) | set(conf_b)):
        if name == "model":
            continue
        if conf_a.get(name) != conf_b.get(name):
            differences.append(f"client_configuration.{name}: {conf_a.get(name)!r} vs {conf_b.get(name)!r}")
    model_a = rows_a[0]["key"].get("model")
    model_b = rows_b[0]["key"].get("model")
    if model_a == model_b:
        differences.append(f"both row sets are model {model_a!r}; a model comparison needs two models")
    if differences:
        raise NotComparable("the row sets differ in more than the model:\n  " + "\n  ".join(differences))
    return {
        "arm": a["arm"], "repeat": a["repeat"], "seed": a["seed"], "manifest_hash": a["manifest_hash"],
        "prompt_version": a["prompt_version"], "investigator": json.loads(a["investigator"]),
        "shared_client_configuration": {k: v for k, v in conf_a.items() if k != "model"},
        "models": {model_a: _model_record(rows_a[0]), model_b: _model_record(rows_b[0])},
    }


def _model_record(payload: dict[str, Any]) -> dict[str, Any]:
    header = payload.get("header") or {}
    model = dict(header.get("model") or {})
    return {
        "model": model.get("model"), "quantization": model.get("quantization"),
        "parameter_size": model.get("parameter_size"), "digest": model.get("digest"),
        "daemon_version": header.get("daemon_version"), "frozen_head": header.get("frozen_head"),
        "head": header.get("head"),
        "run_id": (header.get("runner") or {}).get("run_id"),
        "gpu": (header.get("runner") or {}).get("gpu"),
    }


# -- pairing and ordering -------------------------------------------------------------------

_DECISION_RANK = {"correct": 2, "abstain": 1, "wrong": 0}


def _order(dimension: str, a: dict[str, Any], b: dict[str, Any]) -> str | None:
    """``"better"`` when B beats A on ``dimension``, ``"worse"``, ``"same"``, or ``None``
    when the dimension does not apply to this case (unlabelled, no link, unmeasured)."""
    if dimension == "decision":
        if a["decision"] is None or b["decision"] is None:
            return None
        ra, rb = _DECISION_RANK[a["decision"]], _DECISION_RANK[b["decision"]]
        return "same" if ra == rb else ("better" if rb > ra else "worse")
    if dimension == "link_2":
        if a["link_2"] is None or b["link_2"] is None:
            return None
        return "same" if a["link_2"] == b["link_2"] else ("better" if b["link_2"] else "worse")
    higher_is_better = {"new_used": True, "productive": True, "rejected": False, "invalid_refs": False, "tokens": False, "wall": False}
    field = {"new_used": "new_used", "productive": "productive_probes", "rejected": "rejected",
             "invalid_refs": "invalid_refs", "tokens": "tokens", "wall": "wall_seconds"}[dimension]
    va, vb = a.get(field), b.get(field)
    if not isinstance(va, (int, float)) or not isinstance(vb, (int, float)):
        return None
    if va == vb:
        return "same"
    return "better" if ((vb > va) == higher_is_better[dimension]) else "worse"


def pair_rows(facts_a: Sequence[dict[str, Any]], facts_b: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    by_a = {f["key"]: f for f in facts_a}
    by_b = {f["key"]: f for f in facts_b}
    paired = []
    for key in sorted(set(by_a) | set(by_b)):
        a, b = by_a.get(key), by_b.get(key)
        entry: dict[str, Any] = {"key": key, "a": a, "b": b, "paired": a is not None and b is not None}
        if entry["paired"]:
            entry["verdict"] = {d: _order(d, a, b) for d in DIMENSIONS}
        paired.append(entry)
    return paired


def _aggregate(facts: Sequence[dict[str, Any]]) -> dict[str, Any]:
    labelled = [f for f in facts if f["decision"] is not None]
    link_rows = [f for f in facts if f["link_2"] is not None]
    walls = [f["wall_seconds"] for f in facts if isinstance(f["wall_seconds"], (int, float))]
    return {
        "rows": len(facts),
        "completed_strict": sum(1 for f in facts if f["completed_strict"]),
        "degraded": sum(1 for f in facts if f["degraded"]),
        "truncated": sum(1 for f in facts if f["truncated"]),
        "unparseable_calls": sum(f["unparseable"] or 0 for f in facts),
        "labelled": len(labelled),
        "decisions": dict(Counter(f["decision"] for f in labelled)),
        "link_1_recovered": sum(1 for f in facts if f["link_1"]),
        "link_1_defined": sum(1 for f in facts if f["link_1"] is not None),
        "link_2_recovered": sum(1 for f in link_rows if f["link_2"]),
        "link_2_defined": len(link_rows),
        "probes_total": sum(f["probes_total"] for f in facts),
        "productive_probes": sum(f["productive_probes"] for f in facts),
        "unproductive_probes": sum(f["unproductive_probes"] for f in facts),
        "probe_tools": dict(Counter(t for f in facts for t in f["probes"])),
        "cases_using_new_evidence": sum(1 for f in facts if (f["new_used"] or 0) > 0),
        "new_returned_total": sum(f["new_returned"] or 0 for f in facts),
        "new_shown_total": sum(f["new_shown"] or 0 for f in facts),
        "new_used_total": sum(f["new_used"] or 0 for f in facts),
        "hypothesis_changed_after_tool": sum(1 for f in facts if f["hypothesis_changed_after_tool"]),
        "rejected_total": sum(f["rejected"] or 0 for f in facts),
        "rows_with_rejection": sum(1 for f in facts if (f["rejected"] or 0) > 0),
        "invalid_refs_total": sum(f["invalid_refs"] or 0 for f in facts if isinstance(f["invalid_refs"], int)),
        "evidence_correctness_min": min((f["evidence_correctness"] for f in facts if isinstance(f["evidence_correctness"], (int, float))), default=None),
        "unsupported_total": sum(f["unsupported"] or 0 for f in facts),
        "model_calls": sum(f["model_calls"] or 0 for f in facts),
        "tool_calls": sum(f["tool_calls"] or 0 for f in facts),
        "prompt_tokens": sum(f["prompt_tokens"] or 0 for f in facts),
        "completion_tokens": sum(f["completion_tokens"] or 0 for f in facts),
        "tokens": sum(f["tokens"] or 0 for f in facts),
        "wall_seconds_total": round(sum(walls), 1),
        "wall_seconds_median": _median(walls, 1),
        "ram_min_available_bytes": min((f["ram"]["preflight_available_bytes"] for f in facts if f["ram"].get("preflight_available_bytes") is not None), default=None),
        "model_vram_bytes_max": max((f["ram"].get("model_vram_bytes") or 0 for f in facts), default=None),
    }


def compare(rows_a: Sequence[dict[str, Any]], rows_b: Sequence[dict[str, Any]], *, manifest_digest: str | None = None, telemetry_hashes: dict[str, str] | None = None) -> dict[str, Any]:
    identity = assert_comparable(rows_a, rows_b)
    facts_a = [row_facts(r, manifest_digest=manifest_digest, telemetry_hashes=telemetry_hashes) for r in rows_a]
    facts_b = [row_facts(r, manifest_digest=manifest_digest, telemetry_hashes=telemetry_hashes) for r in rows_b]
    paired = pair_rows(facts_a, facts_b)
    both = [p for p in paired if p["paired"]]
    tallies = {
        d: dict(Counter(p["verdict"][d] for p in both if p["verdict"][d] is not None)) for d in DIMENSIONS
    }
    model_a, model_b = rows_a[0]["key"]["model"], rows_b[0]["key"]["model"]
    per_compute = {}
    for name, facts in ((model_a, facts_a), (model_b, facts_b)):
        agg = _aggregate(facts)
        tokens = agg["tokens"] or 0
        per_compute[name] = {
            "new_ids_used_per_100k_tokens": round(agg["new_used_total"] / tokens * 100_000, 3) if tokens else None,
            "link_2_per_100k_tokens": round(agg["link_2_recovered"] / tokens * 100_000, 3) if tokens else None,
            "productive_probes_per_100k_tokens": round(agg["productive_probes"] / tokens * 100_000, 3) if tokens else None,
        }
    return {
        "identity": identity,
        "model_a": model_a, "model_b": model_b,
        "aggregate": {model_a: _aggregate(facts_a), model_b: _aggregate(facts_b)},
        "contribution_per_compute": per_compute,
        "paired_cases": len(both),
        "unpaired_cases": [p["key"] for p in paired if not p["paired"]],
        "tallies_b_vs_a": tallies,
        "cases": paired,
        "orderings": {
            "decision": "correct > abstain > wrong, against the row's label",
            "link_2": "recovered > not, where one is defined",
            "new_used": "more new evidence ids cited in accepted final claims",
            "productive": "more probes that returned at least one new id",
            "rejected": "fewer rejected model claims",
            "invalid_refs": "fewer cited ids that do not exist",
            "tokens": "fewer total tokens", "wall": "less wall time",
        },
        "caveats": [
            "twenty development cases: a model-selection set, no significance test is computed",
            "link_2 is citation-pair recovery, not proof the explanation is right; claim support is the blind review",
            "the two models differ in parameters AND quantisation AND possibly residency; the identity block records each",
            "wall time depends on the hardware each row records under header.runner.gpu; compare it only across the same hardware",
        ],
    }


# -- rendering ------------------------------------------------------------------------------


def _fmt(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.3g}"
    return str(value)


def render(result: dict[str, Any]) -> str:
    a, b = result["model_a"], result["model_b"]
    ident = result["identity"]
    out = [
        f"# D1 paired model comparison: `{a}` (A) vs `{b}` (B)",
        "",
        f"Arm {ident['arm']}, repeat {ident['repeat']}, seed {ident['seed']}, manifest `{str(ident['manifest_hash'])[:12]}`, "
        f"investigator `{ident['prompt_version']}` (prompt hashes identical on every row of both sets). "
        f"Paired cases: {result['paired_cases']}; unpaired: {', '.join(result['unpaired_cases']) or 'none'}. "
        "MEASURED from the rows; no interpretation.",
        "",
        "## The two models, as the daemon described them",
        "",
        "| | model | quantisation | parameters | digest | daemon | run head |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for label, name in (("A", a), ("B", b)):
        m = ident["models"][name]
        out.append(f"| {label} | `{m['model']}` | {m['quantization']} | {m['parameter_size']} | `{str(m['digest'])[:12]}` | {m['daemon_version']} | `{m['head']}` |")
    shared = ident["shared_client_configuration"]
    out += ["", "Shared client configuration: `" + json.dumps(shared, sort_keys=True, default=str) + "`", ""]
    out += ["## Aggregates", "", f"| metric | A `{a}` | B `{b}` |", "| --- | ---: | ---: |"]
    agg_a, agg_b = result["aggregate"][a], result["aggregate"][b]
    for metric in agg_a:
        va, vb = agg_a[metric], agg_b[metric]
        out.append(f"| {metric} | {_fmt(va) if not isinstance(va, dict) else json.dumps(va)} | {_fmt(vb) if not isinstance(vb, dict) else json.dumps(vb)} |")
    out += ["", "### Contribution per compute", "", "| per 100k tokens | A | B |", "| --- | ---: | ---: |"]
    for metric in result["contribution_per_compute"][a]:
        out.append(f"| {metric} | {_fmt(result['contribution_per_compute'][a][metric])} | {_fmt(result['contribution_per_compute'][b][metric])} |")
    out += ["", "## B against A, paired by case", "", "| dimension | B better | same | B worse | not applicable |", "| --- | ---: | ---: | ---: | ---: |"]
    for d in DIMENSIONS:
        t = result["tallies_b_vs_a"][d]
        applicable = sum(t.values())
        out.append(f"| {d} ({result['orderings'][d]}) | {t.get('better', 0)} | {t.get('same', 0)} | {t.get('worse', 0)} | {result['paired_cases'] - applicable} |")
    out += [
        "", "## Per case", "",
        "| case | label | A disp | B disp | A probes | B probes | A new ret/shown/used | B new ret/shown/used | A L2 | B L2 | A rej | B rej | A tokens | B tokens | A wall s | B wall s | B vs A |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for p in result["cases"]:
        fa, fb = p["a"] or {}, p["b"] or {}
        verdicts = "; ".join(f"{d}:{v}" for d, v in (p.get("verdict") or {}).items() if v and v != "same") or ("same" if p["paired"] else "unpaired")
        out.append(
            f"| {p['key']} | {_fmt(fa.get('label') or fb.get('label'))} | {_fmt(fa.get('disposition'))} | {_fmt(fb.get('disposition'))} | "
            f"{','.join(fa.get('probes') or []) or '-'} | {','.join(fb.get('probes') or []) or '-'} | "
            f"{_fmt(fa.get('new_returned'))}/{_fmt(fa.get('new_shown'))}/{_fmt(fa.get('new_used'))} | {_fmt(fb.get('new_returned'))}/{_fmt(fb.get('new_shown'))}/{_fmt(fb.get('new_used'))} | "
            f"{_fmt(fa.get('link_2'))} | {_fmt(fb.get('link_2'))} | {_fmt(fa.get('rejected'))} | {_fmt(fb.get('rejected'))} | "
            f"{_fmt(fa.get('tokens'))} | {_fmt(fb.get('tokens'))} | {_fmt(fa.get('wall_seconds'))} | {_fmt(fb.get('wall_seconds'))} | {verdicts} |"
        )
    out += ["", "## Caveats", ""] + [f"- {c}" for c in result["caveats"]]
    return "\n".join(out)


# -- command --------------------------------------------------------------------------------


def load_rows(out_dir: Path, arm: str, model: str, digest: str, entries: Sequence[Any], repeat: int) -> tuple[list[dict[str, Any]], dict[str, int]]:
    layout = Layout(Path(out_dir), arm, model, digest)
    return select_rows(completed_rows(layout.rows_dir), entries, digest, model=model, repeat=repeat)


def compare_models(
    *, out_dir: Path, arm_letter: str, models: Sequence[str], repeat: int = 1,
    spec: Any = None, argv: list[str] | None = None,
    log: Callable[[str], None] = lambda text: print(text, file=sys.stderr),
) -> int:
    if len(models) != 2:
        raise SystemExit("compare needs exactly two models")
    payload, entries, digest = read_manifest(out_dir)
    telemetry_hashes = {e.key: e.telemetry_hash for e in entries}
    sets = []
    for model in models:
        rows, excluded = load_rows(out_dir, arm_letter, model, digest, entries, repeat)
        log(f"{model}: {len(rows)} row(s) under manifest {digest[:12]}; excluded {excluded or 'none'}")
        sets.append(rows)
    try:
        result = compare(sets[0], sets[1], manifest_digest=digest, telemetry_hashes=telemetry_hashes)
    except NotComparable as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    layout = Layout(Path(out_dir), arm_letter, models[0], digest)
    record = RunRecord.start(layout, "compare", argv=argv, spec=spec)
    result["head"] = head()
    result["expected_cases"] = len(entries)
    result["compare_run_id"] = record.run_id
    json_path = write_json(layout.compare_json(models[1], repeat), result)
    md_path = write_text(layout.compare_md(models[1], repeat), render(result))
    print(render(result))
    log(f"wrote {md_path} and {json_path}")
    record.finish(0, {"paired": result["paired_cases"], "unpaired": len(result["unpaired_cases"])})
    return 0
