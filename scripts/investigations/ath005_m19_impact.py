"""What the invariant-satisfying rule WOULD produce for the one affected burst.

Computes, without modifying any rule source, the follow-up the current code picks and
the follow-up the invariant ("first success strictly after burst_end") would pick, for
the flaws.cloud SecurityMokey burst that is M19 manifest case flaws_cloud/CASE-005.
"""
from __future__ import annotations
import sys
from datetime import timedelta
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]  # scripts/investigations/ -> repo root
sys.path.insert(0, str(ROOT / "src"))
import pandas as pd  # noqa
from ath.schema import EVENT_LOGON  # noqa
from ath.telemetry.cloudtrail_source import CloudTrailSource  # noqa

FLAWS = Path(r"<local-checkout>\agentic-threat-hunter"
             r"\data\external\flaws_cloud\raw")
WINDOW = timedelta(minutes=15)

t = CloudTrailSource(FLAWS).load().tables[EVENT_LOGON]
burst_start = pd.Timestamp("2017-05-26 22:25:09+00:00")
burst_end = pd.Timestamp("2017-05-26 22:29:16+00:00")
s = t[(t["user"] == "SecurityMokey") & (t["action"] == "success")
      & (t["source_ip"] == "255.253.125.115")
      & (t["device"] == "aws:811596193553/us-east-1")].sort_values("timestamp")

cur = s[(s["timestamp"] >= burst_start) & (s["timestamp"] <= burst_end + WINDOW)]
fixed = s[(s["timestamp"] > burst_end) & (s["timestamp"] <= burst_end + WINDOW)]
during = s[(s["timestamp"] >= burst_start) & (s["timestamp"] <= burst_end)]

print("burst_start", burst_start, " burst_end", burst_end)
print("CURRENT  follow-up rows:", len(cur))
r = cur.iloc[0]
print("  first =", r["event_id"], r["timestamp"],
      "interval =", (r["timestamp"] - burst_end).total_seconds(), "s")
print("INVARIANT follow-up rows:", len(fixed))
r2 = fixed.iloc[0]
print("  first =", r2["event_id"], r2["timestamp"],
      "interval =", (r2["timestamp"] - burst_end).total_seconds(), "s")
print("successes_during_burst (burst_start..burst_end inclusive):", len(during))
print("severity now / under invariant: CRITICAL / CRITICAL (a genuine follow-up exists)")

import json
man = json.load(open(ROOT / "reports/m19/ablation/MANIFEST.json"))
case = [c for c in man["cases"]
        if c["corpus"] == "flaws_cloud" and c["case_id"] == "CASE-005"][0]
ids = set(case["evidence_ids"])
print("\nmanifest CASE-005 evidence_ids:", len(ids))
print("  contains current success id ", r["event_id"], ":", r["event_id"] in ids)
print("  contains invariant success id", r2["event_id"], ":", r2["event_id"] in ids)
