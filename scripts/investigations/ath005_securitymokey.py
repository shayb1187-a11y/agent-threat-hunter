"""Detail on the one negative-interval burst (flaws.cloud, SecurityMokey)."""
from __future__ import annotations
import sys
from datetime import timedelta
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS  # noqa
from ath.telemetry.cloudtrail_source import CloudTrailSource  # noqa

FLAWS = Path(r"<local-checkout>\agentic-threat-hunter"
             r"\data\external\flaws_cloud\raw")
t = CloudTrailSource(FLAWS).load().tables[EVENT_LOGON]
import pandas as pd
burst_end = pd.Timestamp("2017-05-26 22:29:16+00:00")
burst_start = pd.Timestamp("2017-05-26 22:25:09+00:00")  # printed below if wrong
sel = t[(t["user"] == "SecurityMokey")]
sel = sel.sort_values("timestamp")
lo = burst_end - timedelta(minutes=30)
hi = burst_end + timedelta(minutes=30)
w = sel[(sel["timestamp"] >= lo) & (sel["timestamp"] <= hi)]
pd.set_option("display.width", 200)
print(w[["event_id", "timestamp", "action", "source_ip", "device"]].to_string())
succ = w[w["action"] == "success"]
print("\nsuccesses in +/-30min:", len(succ))
for _, r in succ.iterrows():
    print(f"  {r['event_id']} {r['timestamp']} ip={r['source_ip']} "
          f"delta_vs_burst_end={(r['timestamp'] - burst_end).total_seconds()}s")
