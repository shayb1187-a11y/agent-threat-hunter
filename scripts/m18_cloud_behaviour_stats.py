"""M18-7 measurement: how cloud control-plane behaviour is distributed, per actor.

Why this script exists, and what it deliberately does not do
------------------------------------------------------------
Three of the five attack_data_aws captures are discovery techniques -- T1526 Cloud
Service Discovery and two T1580 Cloud Infrastructure Discovery captures -- and every one
of them is made of calls that are individually unremarkable. What names them is *breadth*
and *rate*: 1,071 calls across 19 services in three minutes, 1,150 AccessDenied responses
across 45 services in two hours. A detection for that shape is a threshold, and a
threshold chosen by looking at the attack corpus is not a detection, it is a memory of
that corpus.

So the order is: measure the behaviour in a background corpus first, publish the
distribution, and let the architect pre-register a threshold before any rule runs on the
held-out captures. **This script chooses nothing.** It computes, per actor and per
sliding window, the statistics a discovery rule could be built on; it evaluates a
*candidate grid* the architect supplied in advance, so that "how many actors would this
catch" is answerable per candidate; and it writes both out. No threshold appears here
except that grid, and no rule reads this artifact.

What is measured
----------------
Per actor, over sliding windows of 10 and 60 minutes -- two-pointer over that actor's
sorted event times, never fixed buckets, because a burst that straddles a bucket boundary
is exactly the one a bucketed count would halve -- the maximum within any window of:

* ``read_services``                     distinct services among read-class calls
* ``read_resource_types``               distinct resource types among read-class calls
* ``denied_calls``                      calls the platform refused for want of authority
* ``denied_resource_types``             distinct resource types among those refusals
* ``failed_identity_authority_changes`` authority changes on an identity that the
                                        platform rejected for some *other* reason
* ``identity_delete_revoke_changes``    authority changes that removed something

...plus each actor's totals and the span of their activity. The ``denied`` statistics are
only meaningful because M18-7 made ``decision`` three-valued: until then "denied" meant
any error, and on flaws.cloud the largest contributor to it was one account's throttled
``RunInstances`` retry loop.

Usage::

    python scripts/m18_cloud_behaviour_stats.py attack_data_aws --source cloudtrail \\
        --directory data/external/attack_data_aws/raw --per-file
    python scripts/m18_cloud_behaviour_stats.py flaws_cloud --source cloudtrail \\
        --directory data/external/flaws_cloud/raw --raw-identity
    python scripts/m18_cloud_behaviour_stats.py k8s_ci --source k8s \\
        --directory data/external/k8s_ci/raw --cluster ci
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ath.control_vocab import (  # noqa: E402
    DECISION_ALLOWED,
    DECISION_DENIED,
    DECISION_FAILED,
    DELETE,
    READ,
    REVOKE,
    changes_authority,
    verb_class,
)
from ath.schema import EVENT_CONTROL  # noqa: E402
from ath.telemetry.source import SourceLoadResult  # noqa: E402

# The two window lengths, in minutes. Two rather than one because the same behaviour has
# two signatures: a scanner empties its target list in minutes, and a person working
# through the console takes an hour. A single window would have to be wrong about one.
WINDOWS_MINUTES: tuple[int, ...] = (10, 60)

# The candidate grid, supplied by the architect before any measurement was run and
# reproduced here verbatim. These are the values whose consequences this script reports;
# they are not chosen here, and nothing in this file prefers one of them to another.
CANDIDATE_THRESHOLDS: dict[str, tuple[int, ...]] = {
    "read_services": (5, 10, 20),
    "denied_calls": (10, 25, 50, 100),
    "failed_identity_authority_changes": (3, 5, 10),
    "identity_delete_revoke_changes": (1, 3, 5),
}

TOP_ACTORS = 10
"""How many actors are listed per statistic. A bound on the artifact, not a sample."""


# --------------------------------------------------------------------------------------
# Which rows each statistic is computed over.
#
# One predicate per statistic, each reading the shared control vocabulary and nothing
# else -- no service names, no API names, no error strings. A statistic that named the
# services it was measured on would be a memory of flaws.cloud wearing a function's name.
# --------------------------------------------------------------------------------------


def _is_read(verb: str, resource_type: str, decision: str) -> bool:
    """A read-class call, whatever the platform did with it.

    Refused reads count: a caller enumerating an account it has no rights in produces
    nothing but refusals, and that is the T1580 shape, not an absence of one.
    """
    return verb_class(verb) == READ


def _is_denied(verb: str, resource_type: str, decision: str) -> bool:
    """The platform refused this for want of authority. Not "an error occurred"."""
    return decision == DECISION_DENIED


def _is_failed_identity_change(verb: str, resource_type: str, decision: str) -> bool:
    """An authority change the platform rejected for a reason other than authorization.

    ``changes_authority`` is the identity-object condition on both platforms: AWS' IAM
    service, and Kubernetes' RBAC bindings. A run of these is a caller trying to write
    authority it does not know how to write -- the ``MalformedPolicyDocumentException``
    brute force is ten of them -- which is a different statement from being refused.
    """
    return decision == DECISION_FAILED and changes_authority(verb, resource_type)


def _is_identity_removal(verb: str, resource_type: str, decision: str) -> bool:
    """An authority change that took something away: delete- or revoke-class."""
    return changes_authority(verb, resource_type) and verb_class(verb) in (DELETE, REVOKE)


# name -> (row predicate, what is counted inside the window)
#
# "count" counts qualifying rows; a column name counts *distinct values* of that column
# among them. Both are computed by the same two-pointer; only the accumulator differs.
STATISTICS: dict[str, tuple[Callable[[str, str, str], bool], str]] = {
    "read_services": (_is_read, "service"),
    "read_resource_types": (_is_read, "resource_type"),
    "denied_calls": (_is_denied, "count"),
    "denied_resource_types": (_is_denied, "resource_type"),
    "failed_identity_authority_changes": (_is_failed_identity_change, "count"),
    "identity_delete_revoke_changes": (_is_identity_removal, "count"),
}


# --------------------------------------------------------------------------------------
# The sliding window
# --------------------------------------------------------------------------------------


def window_maxima(
    times: Sequence[int], values: Sequence[Any], window_ns: int,
) -> tuple[int, list[int]]:
    """Maximum over every window of ``window_ns``, and the value at each event.

    Two pointers over one actor's sorted event times. The right pointer admits one event;
    the left pointer retires every event that has fallen more than ``window_ns`` behind
    it; whatever is between them is one window, and its value is read off an accumulator
    maintained incrementally. Every maximal window ends at an event, so a window ending at
    each event is all of them.

    Fixed buckets were the alternative and are wrong in a way that matters here: a burst
    of twelve services spanning 09:58--10:02 is six services in each of two ten-minute
    buckets, and the behaviour being measured disappears at exactly the rate a scanner
    produces it.

    Args:
        times: Event times as integer nanoseconds, sorted ascending.
        values: One value per event. ``None`` entries count toward the window's *size*
            but contribute no distinct value -- which is how "count" is expressed as the
            same computation as "distinct".
        window_ns: Window length in nanoseconds. A window is inclusive at both ends: two
            events exactly ``window_ns`` apart are in the same window.

    Returns:
        ``(maximum, per_event)`` -- the largest window value seen, and the value of the
        window ending at each event, in event order. ``(0, [])`` for no events.
    """
    if not times:
        return 0, []

    counts: Counter = Counter()
    distinct = 0        # values with a live occurrence, when values are being counted
    size = 0            # events in the window, when rows are being counted
    counting_rows = values is None or all(value is None for value in values)
    left = 0
    best = 0
    per_event: list[int] = []

    for right, time_ns in enumerate(times):
        value = None if values is None else values[right]
        size += 1
        if value is not None:
            if counts[value] == 0:
                distinct += 1
            counts[value] += 1

        while times[left] < time_ns - window_ns:
            gone = None if values is None else values[left]
            size -= 1
            if gone is not None:
                counts[gone] -= 1
                if counts[gone] == 0:
                    distinct -= 1
            left += 1

        current = size if counting_rows else distinct
        per_event.append(current)
        best = max(best, current)

    return best, per_event


def _service_of_row(resource_type: str) -> str:
    """The service half of a canonical resource type, or the whole of it when there is no
    family (``"iam:user-policy"`` -> ``"iam"``, ``"rolebindings"`` -> ``"rolebindings"``)."""
    return resource_type.split(":", 1)[0]


def measure_actor(
    frame: pd.DataFrame, window_minutes: Iterable[int] = WINDOWS_MINUTES,
) -> dict[str, Any]:
    """Every statistic for one actor's control rows, at every window length.

    Args:
        frame: That actor's rows, any order; sorted here so a caller cannot get a
            different answer by handing them over differently.

    Returns:
        ``{"rows", "first", "last", "span_hours", "totals", "windows", "days"}`` --
        ``windows[str(minutes)][statistic]`` is the sliding-window maximum, and
        ``days[str(minutes)][statistic][value]`` maps a window value to the set of days on
        which a window reaching it ended, which is what an actor-day count is made of.
    """
    frame = frame.sort_values("timestamp", kind="stable")
    times = frame["timestamp"].astype("int64").tolist()
    verbs = frame["verb"].astype("string").fillna("").tolist()
    resources = frame["resource_type"].astype("string").fillna("").tolist()
    decisions = frame["decision"].astype("string").fillna("").tolist()
    days = frame["timestamp"].dt.strftime("%Y-%m-%d").tolist()

    totals: dict[str, int] = {}
    windows: dict[str, dict[str, int]] = {str(m): {} for m in window_minutes}
    day_hits: dict[str, dict[str, dict[int, set[str]]]] = {
        str(m): {} for m in window_minutes
    }

    for name, (predicate, counted) in STATISTICS.items():
        keep = [
            index for index in range(len(times))
            if predicate(verbs[index], resources[index], decisions[index])
        ]
        subset_times = [times[i] for i in keep]
        subset_days = [days[i] for i in keep]
        if counted == "count":
            subset_values = [None] * len(keep)
            totals[name] = len(keep)
        elif counted == "service":
            subset_values = [_service_of_row(resources[i]) for i in keep]
            totals[name] = len({v for v in subset_values})
        else:
            subset_values = [resources[i] for i in keep]
            totals[name] = len({v for v in subset_values})

        for minutes in window_minutes:
            window_ns = minutes * 60 * 1_000_000_000
            best, per_event = window_maxima(subset_times, subset_values, window_ns)
            windows[str(minutes)][name] = best
            by_value: dict[int, set[str]] = {}
            for value, day in zip(per_event, subset_days):
                by_value.setdefault(value, set()).add(day)
            day_hits[str(minutes)][name] = by_value

    decision_totals = Counter(decisions)
    return {
        "rows": len(frame),
        "first": str(frame["timestamp"].iloc[0]),
        "last": str(frame["timestamp"].iloc[-1]),
        "span_hours": round(
            (times[-1] - times[0]) / 3_600_000_000_000, 3
        ) if times else 0.0,
        "days_active": len(set(days)),
        "decisions": {
            key: int(decision_totals.get(key, 0))
            for key in (DECISION_ALLOWED, DECISION_DENIED, DECISION_FAILED)
        },
        "totals": totals,
        "windows": windows,
        "_day_hits": day_hits,
    }


def measure_table(controls: pd.DataFrame) -> dict[str, dict[str, Any]]:
    """Every actor in one control table, keyed by actor name."""
    if controls.empty:
        return {}
    actors: dict[str, dict[str, Any]] = {}
    for actor, frame in controls.groupby(controls["actor"].astype("string").fillna("")):
        actors[str(actor)] = measure_actor(frame)
    return actors


# --------------------------------------------------------------------------------------
# Distributions and the candidate grid
# --------------------------------------------------------------------------------------


def _percentiles(values: list[int]) -> dict[str, float]:
    """p50/p90/p99/max over the per-actor window maxima, plus how many actors there were."""
    if not values:
        return {"actors": 0, "p50": 0, "p90": 0, "p99": 0, "max": 0}
    series = pd.Series(values, dtype="float64")
    return {
        "actors": len(values),
        "p50": float(series.quantile(0.50)),
        "p90": float(series.quantile(0.90)),
        "p99": float(series.quantile(0.99)),
        "max": float(series.max()),
    }


def distributions(actors: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The distribution over actors of each window maximum, per window length."""
    out: dict[str, Any] = {}
    for minutes in WINDOWS_MINUTES:
        key = str(minutes)
        out[key] = {
            name: _percentiles([a["windows"][key][name] for a in actors.values()])
            for name in STATISTICS
        }
    return out


def threshold_table(actors: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """For each candidate: how many actors reach it, and on how many actor-days.

    An actor-day counts once per (actor, day) on which a qualifying window *ended*, which
    is the unit an alert queue is measured in: an actor who scans every morning for a
    month is thirty alerts, not one.
    """
    out: dict[str, Any] = {}
    for minutes in WINDOWS_MINUTES:
        key = str(minutes)
        per_statistic: dict[str, Any] = {}
        for name, candidates in CANDIDATE_THRESHOLDS.items():
            per_threshold: dict[str, Any] = {}
            for threshold in candidates:
                matching = [
                    name_ for name_, actor in actors.items()
                    if actor["windows"][key][name] >= threshold
                ]
                actor_days = 0
                for actor in actors.values():
                    days: set[str] = set()
                    for value, day_set in actor["_day_hits"][key][name].items():
                        if value >= threshold:
                            days |= day_set
                    actor_days += len(days)
                per_threshold[str(threshold)] = {
                    "actors": len(matching),
                    "actor_days": actor_days,
                    "actors_named": sorted(matching)[:TOP_ACTORS],
                }
            per_statistic[name] = per_threshold
        out[key] = per_statistic
    return out


def top_actors(
    actors: dict[str, dict[str, Any]],
    identity_types: dict[str, dict[str, int]],
    denied_codes: dict[str, dict[str, int]],
) -> dict[str, Any]:
    """The ten highest actors per statistic, with who they are and what refused them."""
    out: dict[str, Any] = {}
    for minutes in WINDOWS_MINUTES:
        key = str(minutes)
        per_statistic: dict[str, Any] = {}
        for name in STATISTICS:
            ranked = sorted(
                actors.items(), key=lambda kv: (-kv[1]["windows"][key][name], kv[0]),
            )[:TOP_ACTORS]
            per_statistic[name] = [
                {
                    "actor": actor,
                    "value": stats["windows"][key][name],
                    "total": stats["totals"][name],
                    "rows": stats["rows"],
                    "span_hours": stats["span_hours"],
                    "identity_types": identity_types.get(actor, {}),
                    "denied_error_codes": dict(
                        sorted(denied_codes.get(actor, {}).items(),
                               key=lambda kv: -kv[1])[:5]
                    ),
                }
                for actor, stats in ranked
            ]
        out[key] = per_statistic
    return out


def _strip_day_hits(actors: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """The per-actor records as they are written out: day sets are an intermediate."""
    return [
        {"actor": actor, **{k: v for k, v in stats.items() if k != "_day_hits"}}
        for actor, stats in sorted(actors.items())
    ]


# --------------------------------------------------------------------------------------
# Loading, and the raw pass that the canonical row cannot answer
# --------------------------------------------------------------------------------------


def load_source(kind: str, directory: Path, cluster: str) -> SourceLoadResult:
    if kind == "cloudtrail":
        from ath.telemetry.cloudtrail_source import CloudTrailSource
        return CloudTrailSource(directory).load()
    if kind == "k8s":
        from ath.telemetry.k8s_audit_source import K8sAuditSource
        return K8sAuditSource(directory, cluster=cluster).load()
    raise SystemExit(f"unknown source kind {kind!r}")


def raw_identity_pass(directory: Path) -> dict[str, Any]:
    """One extra pass over the raw CloudTrail records, for the three things a row lacks.

    ``userIdentity.type`` (is this a human, a role session, an AWS service?), the error
    codes behind each actor's refusals, and the before/after decision cross-tab computed
    on the *same* records by the old rule and the new one -- which is the only way to
    state what the tri-state changed without re-running an older checkout.

    The adapter's own private readers are used deliberately: a second implementation of
    "who is the caller" here would be a second answer to that question.
    """
    from ath.telemetry.cloudtrail_source import (  # noqa: PLC0415
        AUTH_EVENTS,
        _classify,
        _control_decision,
        _iter_payloads,
        _principal,
        _verdict,
    )

    identity_types: dict[str, Counter] = {}
    denied_codes: dict[str, Counter] = {}
    error_codes: Counter = Counter()
    cross_tab: Counter = Counter()

    files = sorted(
        p for p in directory.iterdir()
        if p.is_file() and _classify(p.name) is not None
    )
    for _name, _parsed, records in _iter_payloads(files):
        for record in records:
            if not isinstance(record, dict):
                continue
            if str(record.get("eventName") or "") in AUTH_EVENTS:
                continue
            identity = record.get("userIdentity") or {}
            identity = identity if isinstance(identity, dict) else {}
            actor = _principal(identity)
            if not actor:
                continue
            identity_types.setdefault(actor, Counter())[
                str(identity.get("type") or "")
            ] += 1
            after = _control_decision(record)
            before = "denied" if _verdict(record) == "failure" else "allowed"
            cross_tab[f"{before}->{after}"] += 1
            code = str(record.get("errorCode") or "")
            if code:
                error_codes[code] += 1
            if after == DECISION_DENIED:
                denied_codes.setdefault(actor, Counter())[code or "(no code)"] += 1

    return {
        "identity_types": {a: dict(c) for a, c in identity_types.items()},
        "denied_error_codes": {a: dict(c) for a, c in denied_codes.items()},
        "error_code_histogram": dict(error_codes.most_common(25)),
        "decision_cross_tab": dict(cross_tab),
    }


def decision_distribution(controls: pd.DataFrame) -> dict[str, Any]:
    """The canonical table's decision counts, and what they were under the old rule.

    The BEFORE column is not an estimate. The old rule was "any error is denied", so the
    old ``denied`` is exactly the new ``denied`` plus the new ``failed`` and the old
    ``allowed`` is the new ``allowed`` -- for Kubernetes by construction, and for
    CloudTrail up to records carrying a ``ConsoleLogin`` response on a management row,
    which the raw cross-tab in the same artifact counts directly.
    """
    after = Counter(controls["decision"].astype("string").fillna("").tolist())
    return {
        "after": {key: int(after.get(key, 0)) for key in
                  (DECISION_ALLOWED, DECISION_DENIED, DECISION_FAILED)},
        "before": {
            DECISION_ALLOWED: int(after.get(DECISION_ALLOWED, 0)),
            DECISION_DENIED: int(after.get(DECISION_DENIED, 0))
            + int(after.get(DECISION_FAILED, 0)),
        },
        "rows": int(len(controls)),
    }


def _capture_of(source_ref: str) -> str:
    """Which file a canonical row came from: ``"eventID=...;File=<name>"``."""
    for part in str(source_ref).split(";"):
        if part.startswith("File="):
            return part[len("File="):]
    return "(unknown)"


def corpus_record(controls: pd.DataFrame, raw: dict[str, Any]) -> dict[str, Any]:
    """Everything measured about one control table."""
    actors = measure_table(controls)
    return {
        "actor_count": len(actors),
        "decision_distribution": decision_distribution(controls),
        "distribution": distributions(actors),
        "thresholds": threshold_table(actors),
        "top_actors": top_actors(
            actors, raw.get("identity_types", {}), raw.get("denied_error_codes", {}),
        ),
        "actors": _strip_day_hits(actors),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("corpus")
    parser.add_argument("--source", choices=("cloudtrail", "k8s"), required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--cluster", default="external")
    parser.add_argument("--per-file", action="store_true",
                        help="Also measure each capture file on its own (attack_data_aws "
                             "is one ATT&CK technique per file).")
    parser.add_argument("--raw-identity", action="store_true",
                        help="Re-read the raw records for userIdentity.type, the error "
                             "codes behind each actor's denials, and the before/after "
                             "decision cross-tab.")
    parser.add_argument("--out-dir", type=Path,
                        default=ROOT / "reports" / "m18" / "cloud_behaviour")
    args = parser.parse_args()

    started = time.perf_counter()
    result = load_source(args.source, args.directory, args.cluster)
    load_seconds = time.perf_counter() - started
    controls = result.tables[EVENT_CONTROL]

    raw: dict[str, Any] = {}
    raw_seconds = 0.0
    if args.raw_identity or args.per_file:
        if args.source != "cloudtrail":
            raise SystemExit("--raw-identity and --per-file are CloudTrail-only")
    if args.raw_identity:
        raw_started = time.perf_counter()
        raw = raw_identity_pass(args.directory)
        raw_seconds = time.perf_counter() - raw_started

    measure_started = time.perf_counter()
    record: dict[str, Any] = {
        "corpus": args.corpus,
        "source": {"kind": args.source, "directory": str(args.directory)},
        "windows_minutes": list(WINDOWS_MINUTES),
        "candidate_thresholds": {k: list(v) for k, v in CANDIDATE_THRESHOLDS.items()},
        "statistics": {
            name: {
                "rows": predicate.__doc__.splitlines()[0] if predicate.__doc__ else "",
                "counts": counted,
            }
            for name, (predicate, counted) in STATISTICS.items()
        },
        "pooled": corpus_record(controls, raw),
    }
    if raw:
        record["raw"] = {
            "error_code_histogram": raw["error_code_histogram"],
            "decision_cross_tab": raw["decision_cross_tab"],
        }

    if args.per_file:
        captures = controls["source_ref"].astype("string").fillna("").map(_capture_of)
        record["per_capture"] = {
            str(capture): corpus_record(controls[captures == capture], raw)
            for capture in sorted(captures.unique())
        }

    record["cost"] = {
        "load_seconds": round(load_seconds, 1),
        "raw_pass_seconds": round(raw_seconds, 1),
        "measure_seconds": round(time.perf_counter() - measure_started, 1),
        "control_rows": int(len(controls)),
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"{args.corpus}.json"
    out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")

    pooled = record["pooled"]
    print(f"\n{args.corpus}: {len(controls):,} control rows, "
          f"{pooled['actor_count']} actor(s)")
    print(f"  decision  before {pooled['decision_distribution']['before']}")
    print(f"            after  {pooled['decision_distribution']['after']}")
    for minutes in WINDOWS_MINUTES:
        print(f"  -- {minutes}-minute windows --")
        for name in STATISTICS:
            stats = pooled["distribution"][str(minutes)][name]
            print(f"    {name:36s} p50={stats['p50']:.0f} p90={stats['p90']:.0f} "
                  f"p99={stats['p99']:.0f} max={stats['max']:.0f}")
    print(f"  written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
