"""ATH-005 negative-interval reach measurement (scratch; not part of the suite).

Runs ATH-005 alone over every corpus available in this worktree and reports, per
finding: succeeded flag, severity, and (first follow-up timestamp - burst_end) in
seconds. Counts findings whose interval is negative -- i.e. the "follow-up" success
happened *before* the last failure of the burst.

Usage:  python scratch/ath005_reach.py [--flaws]
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # scripts/investigations/ -> repo root
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd  # noqa: E402

from ath.hunting import get_detector  # noqa: E402
from ath.hunting.base import HuntConfig  # noqa: E402
from ath.schema import (  # noqa: E402
    EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS,
)
from ath.telemetry.cloudtrail_source import CloudTrailSource  # noqa: E402
from ath.telemetry.loader import Telemetry, load_telemetry  # noqa: E402

FLAWS = ROOT / "data" / "external" / "flaws_cloud" / "raw"  # fetched by scripts/fetch_external.py


def _telemetry(result) -> Telemetry:
    return Telemetry(
        processes=result.tables[EVENT_PROCESS], network=result.tables[EVENT_NETWORK],
        logons=result.tables[EVENT_LOGON], controls=result.tables[EVENT_CONTROL],
    )


def rows(label: str, tel: Telemetry) -> list[dict]:
    det = get_detector("ATH-005", config=HuntConfig())
    out = []
    for f in det.detect(tel):
        burst_end = f.metadata["burst_end"]
        succ = [e for e in f.evidence if e.summary.startswith("SUCCESSFUL")]
        interval = None
        if succ:
            interval = (succ[0].timestamp - burst_end).total_seconds()
        out.append({
            "corpus": label,
            "user": f.user,
            "device": f.device,
            "burst_end": str(burst_end),
            "succeeded": f.metadata["succeeded"],
            "severity": f.severity.name,
            "interval_s": interval,
            "reason": f.reason,
        })
    return out


def main() -> None:
    results: list[dict] = []

    # (a) synthetic dataset shipped in this worktree
    raw = ROOT / "data" / "raw"
    if (raw / "logon_events.csv").exists():
        results += rows("synthetic:data/raw", load_telemetry(raw))
    else:
        print("no data/raw -- run `python main.py generate` first")

    # (b) shaped CloudTrail fixture
    shaped = ROOT / "tests" / "fixtures" / "real_shaped" / "cloudtrail_shaped"
    results += rows("cloudtrail_shaped", _telemetry(CloudTrailSource(shaped).load()))

    # (c) the real flaws.cloud trail (READ-ONLY, opt-in: it is a 250 MB tar)
    if "--flaws" in sys.argv:
        if FLAWS.is_dir():
            results += rows("flaws_cloud", _telemetry(CloudTrailSource(FLAWS).load()))
        else:
            print(f"flaws.cloud raw dir not found at {FLAWS}")

    df = pd.DataFrame(results)
    if df.empty:
        print("no ATH-005 findings anywhere")
        return
    pd.set_option("display.width", 200)
    pd.set_option("display.max_colwidth", 40)
    print(df[["corpus", "user", "device", "burst_end", "succeeded", "severity",
              "interval_s"]].to_string())
    neg = df[df["interval_s"].notna() & (df["interval_s"] < 0)]
    print(f"\ntotal ATH-005 findings: {len(df)}")
    print(f"with a follow-up:       {int(df['succeeded'].sum())}")
    print(f"NEGATIVE interval:      {len(neg)}")
    if len(neg):
        print("\nnegative-interval findings:")
        for _, r in neg.iterrows():
            print(f"  [{r['corpus']}] {r['user']} @{r['device']} "
                  f"severity={r['severity']} interval={r['interval_s']}s")
            print(f"    {r['reason']}")


if __name__ == "__main__":
    main()
