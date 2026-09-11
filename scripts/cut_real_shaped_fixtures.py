"""Cut the real-shaped test fixtures under tests/fixtures/real_shaped/ from data/external/.

Why these exist: 704 green tests missed every value-convention defect one day of real
data found (docs/test-quality-root-causes.md, RC1/RC2). The synthetic generator never
starts ``lsass.exe``; the hand-typed Kubernetes fixture logged execs as ``create``. These
fixtures are *captured records*, trimmed only for size, so a rule or adapter is tested
against the shapes an estate actually emits.

Three cuts:

* ``dedale/``   -- Winlogbeat ECS NDJSON, CLIENT2 on 2024-12-25 (a benign day): the boot
                   chain from ``wininit.exe -> lsass.exe``, service logons, CompatTelRunner
                   spawning PowerShell, LibreOffice opening documents. CC BY 4.0.
* ``k8s_ci/``   -- kube-apiserver audit NDJSON from a Kubernetes CI e2e run: bootstrap
                   ``cluster-admin`` binding to ``system:masters``, per-test-namespace
                   ``cluster-admin`` bindings, a ``get``-verb exec answered 101, a
                   service-account token request, a secret read. Public CI artefact.
* ``cloudtrail_shaped/`` -- synthetic, because flaws.cloud carries no licence: records
                   shaped from the real trail's histogram (``AWSService`` identities with
                   ``invokedBy``, ``AssumedRole`` ARNs, ``RequestLimitExceeded`` /
                   ``UnauthorizedOperation`` ``RunInstances`` floods), delivered as a tar
                   of gzipped members the way the real dump is.

Trimming: DEDALE records lose the ``message`` field (a rendered copy of ``event_data``,
the largest field, unused by the adapter). Nothing else is altered; ``winlog.record_id``
and ``host.name`` stay so label refs still resolve.

Usage::

    python scripts/cut_real_shaped_fixtures.py     # needs data/external/ populated
"""

from __future__ import annotations

import datetime as dt
import gzip
import io
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTERNAL = ROOT / "data" / "external"
OUT = ROOT / "tests" / "fixtures" / "real_shaped"

DEDALE_DAY = EXTERNAL / "dedale" / "winlogbeat" / "D03" / "D03_2024-12-25.jsonl"
K8S_LOG = EXTERNAL / "k8s_ci" / "raw" / "kube-apiserver-audit.2065053743543488512.log"


def _ts(record: dict) -> dt.datetime:
    return dt.datetime.fromisoformat(record["@timestamp"].replace("Z", "+00:00"))


def cut_dedale() -> Path:
    rows = []
    for line in DEDALE_DAY.open(encoding="utf-8"):
        event = json.loads(line)
        if event["host"]["name"] != "CLIENT2.breach.local":
            continue
        if event["winlog"]["event_id"] not in (1, 4624, 4625):
            continue
        rows.append(event)
    rows.sort(key=_ts)

    lsass = next(e for e in rows if (e.get("process") or {}).get("name") == "lsass.exe")
    boot_start = _ts(lsass) - dt.timedelta(seconds=5)
    boot_end = boot_start + dt.timedelta(seconds=90)

    keep: list[dict] = []
    seen_pairs: set[tuple[str, str]] = set()
    seen_logon: set[tuple[str, str]] = set()
    for event in rows:
        stamp = _ts(event)
        eid = event["winlog"]["event_id"]
        proc = event.get("process") or {}
        pair = (str(proc.get("parent", {}).get("name")), str(proc.get("name")))
        if boot_start <= stamp <= boot_end:
            if eid == 1 and pair not in seen_pairs and len([k for k in keep if k["winlog"]["event_id"] == 1]) < 16:
                seen_pairs.add(pair)
                keep.append(event)
            elif eid == 4624:
                data = event["winlog"]["event_data"]
                key = (data.get("TargetUserName", ""), data.get("LogonType", ""))
                if key not in seen_logon and len(seen_logon) < 6:
                    seen_logon.add(key)
                    keep.append(event)
        elif eid == 1 and pair[0] == "CompatTelRunner.exe" and pair[1] == "powershell.exe" and pair not in seen_pairs:
            seen_pairs.add(pair)
            keep.append(event)
        elif eid == 1 and pair in (("cmd.exe", "soffice.exe"), ("soffice.exe", "soffice.bin")) and pair not in seen_pairs:
            seen_pairs.add(pair)
            keep.append(event)
        elif eid == 1 and pair in (("explorer.exe", "msedge.exe"), ("explorer.exe", "firefox.exe")) and pair not in seen_pairs:
            seen_pairs.add(pair)
            keep.append(event)

    keep.sort(key=_ts)
    for event in keep:
        event.pop("message", None)
    out_dir = OUT / "dedale"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "client2_2024-12-25_boot.jsonl"
    out.write_text("".join(json.dumps(e) + "\n" for e in keep), encoding="utf-8")
    (out_dir / "PROVENANCE.md").write_text(
        "# Provenance\n\n"
        "Source: DEDALE (INRIA/IRISA PIRAT), https://doi.org/10.57745/Y5JLDG, "
        "https://dedale.inria.fr/ -- licence CC BY 4.0. Cite the dataset and link the site.\n\n"
        "File: `system_logs_winlogbeat.zip`, member `daily_winlogbeat/D3_H8_2024-12-25T08_*.jsonl.bz2` and "
        "later hours of the same day; host `CLIENT2.breach.local`; Winlogbeat 7.10.2 / ECS 1.5.0.\n\n"
        f"Records: {len(keep)} (Sysmon 1 process creates and Security 4624 logons), the boot chain from "
        "`wininit.exe -> lsass.exe` at 08:20:39Z, service logons, `CompatTelRunner.exe -> powershell.exe`, "
        "LibreOffice (`cmd.exe -> soffice.exe -> soffice.bin`). Benign day (week 1, no attack).\n\n"
        "Trimming: the `message` field was removed (rendered copy of `event_data`). Nothing else altered. "
        "`winlog.record_id` + `host.name` + `winlog.channel` remain the label key.\n\n"
        "Cut by `scripts/cut_real_shaped_fixtures.py`.\n",
        encoding="utf-8",
    )
    print(f"dedale: {len(keep)} records, {out.stat().st_size:,} bytes -> {out}")
    return out


K8S_PICKS = {
    "bootstrap cluster-admin -> system:masters": lambda e, o, ro, role, subj: o.get("resource") == "clusterrolebindings" and e["verb"] == "create" and role == "cluster-admin" and "system:masters" in subj,
    "per-test-namespace cluster-admin -> default SA": lambda e, o, ro, role, subj: o.get("resource") == "clusterrolebindings" and e["verb"] == "create" and role == "cluster-admin" and subj and "system:masters" not in subj,
    "e2e-test-privileged-psp binding": lambda e, o, ro, role, subj: o.get("resource") == "clusterrolebindings" and e["verb"] == "create" and role == "e2e-test-privileged-psp",
    "namespaced rolebinding": lambda e, o, ro, role, subj: o.get("resource") == "rolebindings" and e["verb"] == "create" and bool(ro),
    "get-verb exec answered 101": lambda e, o, ro, role, subj: o.get("resource") == "pods" and o.get("subresource") == "exec" and e["verb"] == "get" and (e.get("responseStatus") or {}).get("code") == 101,
    "service-account token request": lambda e, o, ro, role, subj: o.get("resource") == "serviceaccounts" and o.get("subresource") == "token" and e["verb"] == "create",
    "secret read": lambda e, o, ro, role, subj: o.get("resource") == "secrets" and e["verb"] == "get",
    "Request-level pod get": lambda e, o, ro, role, subj: e.get("level") == "Request" and o.get("resource") == "pods" and e["verb"] == "get",
}


def cut_k8s() -> Path:
    picked: dict[str, list[str]] = {k: [] for k in K8S_PICKS}
    limits = {"per-test-namespace cluster-admin -> default SA": 3, "get-verb exec answered 101": 3}
    for line in K8S_LOG.open(encoding="utf-8"):
        event = json.loads(line)
        if event.get("stage") != "ResponseComplete":
            continue
        o = event.get("objectRef") or {}
        ro = event.get("requestObject")
        ro = ro if isinstance(ro, dict) else {}
        rr = ro.get("roleRef")
        role = rr.get("name") if isinstance(rr, dict) else None
        subj = [s.get("name") for s in (ro.get("subjects") or []) if isinstance(s, dict)]
        for name, pred in K8S_PICKS.items():
            if len(picked[name]) < limits.get(name, 1) and pred(event, o, ro, role, subj):
                picked[name].append(line.rstrip("\n"))
        if all(len(v) >= limits.get(k, 1) for k, v in picked.items()):
            break
    lines = [l for v in picked.values() for l in v]
    lines.sort(key=lambda l: json.loads(l).get("stageTimestamp", ""))
    out_dir = OUT / "k8s_ci"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "kube-apiserver-audit.sample.log"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out_dir / "PROVENANCE.md").write_text(
        "# Provenance\n\n"
        "Source: Kubernetes project CI artefacts, public GCS bucket `kubernetes-ci-logs`, job "
        "`ci-kubernetes-e2e-gci-gce`, run `2065053743543488512`, file "
        "`artifacts/bootstrap-e2e-master/kube-apiserver-audit.log` (kube-apiserver 1.37 on GCE, "
        "2026-06-11). No licence text accompanies the bucket; these are unmodified audit records of a "
        "disposable test cluster, redistributed here as a test fixture with this citation.\n\n"
        f"Records: {len(lines)}, one per line, `audit.k8s.io/v1`, all `ResponseComplete`:\n"
        + "".join(f"- {k}: {len(v)}\n" for k, v in picked.items())
        + "\nNothing altered. Cut by `scripts/cut_real_shaped_fixtures.py`.\n",
        encoding="utf-8",
    )
    print(f"k8s_ci: {len(lines)} records, {out.stat().st_size:,} bytes -> {out}")
    return out


def _ct(event_name, source, identity, *, error=None, region="us-east-1", ip="198.51.100.7",
        n=0, time="2020-06-24T14:40:00Z", params=None, response=None):
    record = {
        "eventVersion": "1.08", "eventTime": time, "eventSource": source, "eventName": event_name,
        "awsRegion": region, "sourceIPAddress": ip, "userAgent": "aws-cli/2.15.0",
        "userIdentity": identity, "requestParameters": params, "responseElements": response,
        "eventID": f"shaped-{event_name.lower()}-{n:04d}", "eventType": "AwsApiCall",
        "managementEvent": True, "recipientAccountId": "811596193553",
    }
    if error:
        record["errorCode"], record["errorMessage"] = error
    return record


def make_cloudtrail_shaped() -> Path:
    iam_user = lambda name: {"type": "IAMUser", "principalId": f"AIDA{name.upper()}", "arn": f"arn:aws:iam::811596193553:user/{name}", "accountId": "811596193553", "userName": name}
    service = lambda svc: {"type": "AWSService", "invokedBy": svc}
    assumed = lambda role, session: {"type": "AssumedRole", "principalId": f"AROA{role.upper()}:{session}", "arn": f"arn:aws:sts::811596193553:assumed-role/{role}/{session}", "accountId": "811596193553",
                                     "sessionContext": {"sessionIssuer": {"type": "Role", "userName": role, "arn": f"arn:aws:iam::811596193553:role/{role}"}}}
    root = {"type": "Root", "principalId": "811596193553", "arn": "arn:aws:iam::811596193553:root", "accountId": "811596193553"}

    hour1, hour2 = [], []
    # The real trail's shape: a RunInstances flood that is 68% of everything, all failing.
    for i in range(40):
        hour1.append(_ct("RunInstances", "ec2.amazonaws.com", iam_user("backup"), n=i, ip="231.216.2.251",
                         time=f"2020-06-24T14:{i % 60:02d}:10Z",
                         error=("Client.RequestLimitExceeded", "Request limit exceeded.") if i % 3 else ("Client.UnauthorizedOperation", "You are not authorized to perform this operation."),
                         params={"instanceType": "p3.16xlarge", "minCount": 1, "maxCount": 1}))
    for i in range(6):
        hour1.append(_ct("DescribeSnapshots", "ec2.amazonaws.com", iam_user("backup"), n=i, ip="231.216.2.251", time=f"2020-06-24T14:4{i}:00Z"))
    # Service-invoked STS: dropped as unattributable before M14 step 1.
    for i in range(8):
        hour1.append(_ct("AssumeRole", "sts.amazonaws.com", service("config.amazonaws.com"), n=i, ip="config.amazonaws.com",
                         time=f"2020-06-24T14:0{i}:30Z", params={"roleArn": "arn:aws:iam::811596193553:role/service-role/config-role-us-west-2", "roleSessionName": "AWSConfig-Describe"}))
    # A no-success failed-AssumeRole burst from one address: the ATH-005 shape seen 35 times.
    for i in range(10):
        hour2.append(_ct("AssumeRole", "sts.amazonaws.com", iam_user("backup"), n=100 + i, ip="231.216.2.251",
                         time=f"2020-06-24T14:4{i // 2}:{(i * 7) % 60:02d}Z",
                         error=("AccessDenied", "User: arn:aws:iam::811596193553:user/backup is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::675916645289:role/Administrators"),
                         params={"roleArn": "arn:aws:iam::675916645289:role/Administrators", "roleSessionName": "x"}))
    # Owner administration: an assumed-role session and a root console login.
    hour2.append(_ct("ConsoleLogin", "signin.amazonaws.com", root, n=1, ip="203.0.113.5", time="2020-06-24T15:02:00Z", response={"ConsoleLogin": "Success"}))
    hour2.append(_ct("AttachUserPolicy", "iam.amazonaws.com", assumed("SummitRouteAudit", "audit"), n=1, ip="203.0.113.5", time="2020-06-24T15:05:00Z",
                     params={"userName": "backup", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}))
    hour2.append(_ct("CreateAccessKey", "iam.amazonaws.com", iam_user("Level6"), n=2, ip="9.240.250.1", time="2020-06-24T15:20:00Z",
                     error=("AccessDenied", "User: arn:aws:iam::811596193553:user/Level6 is not authorized to perform: iam:CreateAccessKey"), params={"userName": "Level6"}))
    hour2.append(_ct("ListBuckets", "s3.amazonaws.com", iam_user("Level6"), n=3, ip="9.240.250.1", time="2020-06-24T15:21:00Z"))

    out_dir = OUT / "cloudtrail_shaped"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "flaws_shaped_cloudtrail_logs.tar"
    with tarfile.open(out, "w") as archive:
        for name, records in (("811596193553_CloudTrail_us-east-1_20200624T1400Z_shaped01.json.gz", hour1),
                              ("811596193553_CloudTrail_us-east-1_20200624T1500Z_shaped02.json.gz", hour2)):
            payload = gzip.compress(json.dumps({"Records": records}).encode("utf-8"))
            info = tarfile.TarInfo(f"flaws_shaped/{name}")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    (out_dir / "PROVENANCE.md").write_text(
        "# Provenance\n\n"
        "Synthetic. flaws.cloud's public CloudTrail dump (Summit Route, 2020) carries no licence "
        "statement, so no record from it is committed. These records are *shaped* from its measured "
        "histogram (`data/external/flaws_cloud/probe_eventname_histogram.json`, M14 step 0): a "
        "`RunInstances` flood failing with `RequestLimitExceeded` / `UnauthorizedOperation`, "
        "`AWSService` identities carrying the caller only in `invokedBy`, `AssumedRole` ARNs with "
        "`sessionIssuer`, a no-success `AssumeRole` burst from one address, a root console login, "
        "and a denied `CreateAccessKey`. Delivered as a tar of gzipped hourly members, the real "
        "delivery form. Account id and addresses are the dump's own anonymised values or TEST-NET.\n\n"
        f"Records: {len(hour1) + len(hour2)} in 2 members. Generated by `scripts/cut_real_shaped_fixtures.py`.\n",
        encoding="utf-8",
    )
    print(f"cloudtrail_shaped: {len(hour1) + len(hour2)} records, {out.stat().st_size:,} bytes -> {out}")
    return out


def main() -> int:
    cut_dedale()
    cut_k8s()
    make_cloudtrail_shaped()
    return 0


if __name__ == "__main__":
    sys.exit(main())
