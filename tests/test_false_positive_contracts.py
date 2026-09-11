"""Every declared false positive is a test, not a sentence.

Each rule declares ``false_positives`` -- prose naming the benign activity that can trip
it. Until now no test exercised any of those sentences, which is how ATH-004 shipped a
pattern that matches ``lsass.exe``'s own image path (docs/test-quality-root-causes.md,
RC3). This module turns the prose into a contract:

* :data:`FP_CASES` holds one case per declared false positive, keyed by rule id and the
  index of the sentence, with a builder that constructs the benign activity in canonical
  rows and an *expectation* that pins the rule's current, honest behaviour on it.
* ``test_every_declared_false_positive_has_a_case`` fails when a rule declares a false
  positive without a case here, or when the sentence drifts away from the case that was
  written for it (each case carries the opening words of the sentence it covers).

Expectations:

* ``silent``  -- the rule handles this benign activity; it must produce no finding.
* ``fires``   -- the rule fires on it. That is a documented cost, and the test pins it so
  the cost cannot grow or shrink unnoticed.
* ``fires:not_high`` -- the rule fires, and grades it below HIGH: a documented cost the
  detection itself has already discounted, pinned so neither the firing nor the grade
  can drift.
* ``fires:target_silent`` / ``fires:target_not_high`` -- the rule fires today, and the
  M15 plan says it should not (or should not at HIGH). The pinned test passes; a second,
  strict-xfail test states the target so the suite turns red *deliberately* when the fix
  lands and the expectation must be updated in the same change.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import pytest

from ath.hunting.base import all_detectors, get_detector
from ath.hunting.finding import Severity
from ath.telemetry.loader import Telemetry

from _builders import at, ctrl, failures, logon, net, proc, telemetry


@dataclass(frozen=True)
class Case:
    rule_id: str
    index: int
    opening: str                      # first words of the declared sentence, drift check
    build: Callable[[], Telemetry]
    expect: str                       # silent | fires | fires:target_silent | fires:target_not_high
    note: str = ""


def _ps(cmd: str, parent: str, **kw) -> dict:
    return proc("powershell.exe", cmd, parent, path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", **kw)


ENC = "SQBtAHAAbwByAHQALQBNAG8AZAB1AGwAZQAgAEEAYwB0AGkAdgBlAEQAaQByAGUAYwB0AG8AcgB5ADsAIABHAGUAdAAtAEEARABDAG8AbQBwAHUAdABlAHIAIAAtAEYAaQBsAHQAZQByACAAKgA="


def _office_env() -> list[dict]:
    """A little ordinary background so single-row cases are not the whole world."""
    return [
        proc("explorer.exe", r"C:\Windows\Explorer.EXE", "userinit.exe", when=at(-30)),
        proc("OUTLOOK.EXE", r'"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"', "explorer.exe", when=at(-25)),
        proc("chrome.exe", r'"C:\Program Files\Google\Chrome\Application\chrome.exe"', "explorer.exe", when=at(-20)),
    ]


FP_CASES: tuple[Case, ...] = (
    # ---------------------------------------------------------------- ATH-001
    Case("ATH-001", 0, "Legitimate Office add-ins", lambda: telemetry(procs=_office_env() + [
        _ps(r"powershell.exe -File C:\Program Files\Contoso\AddIn\refresh.ps1", "EXCEL.EXE")]), "fires"),
    Case("ATH-001", 1, "Line-of-business applications", lambda: telemetry(procs=_office_env() + [
        proc("cscript.exe", r"cscript.exe //nologo C:\Reports\build_monthly.vbs", "EXCEL.EXE")]), "fires"),
    Case("ATH-001", 2, "RPA tooling", lambda: telemetry(procs=_office_env() + [
        proc("cmd.exe", r'cmd.exe /c "C:\Program Files\UiPath\Studio\tools\excel_bridge.bat"', "WINWORD.EXE")]), "fires"),
    Case("ATH-001", 3, "Enterprise document templates", lambda: telemetry(procs=_office_env() + [
        proc("wscript.exe", r"wscript.exe C:\ProgramData\Contoso\Templates\onopen.vbs", "WINWORD.EXE")]), "fires"),
    # ---------------------------------------------------------------- ATH-002
    Case("ATH-002", 0, "Configuration management", lambda: telemetry(procs=[
        proc("CcmExec.exe", r"C:\Windows\CCM\CcmExec.exe", "services.exe", user="SYSTEM"),
        _ps(f"powershell.exe -NoProfile -EncodedCommand {ENC}", "CcmExec.exe", user="SYSTEM")]), "fires",
        "the shipped benign look-alike: fires at MEDIUM, explained by triage"),
    Case("ATH-002", 1, "Software installers", lambda: telemetry(procs=[
        _ps(f"powershell.exe -enc {ENC}", "msiexec.exe", user="SYSTEM")]), "fires"),
    Case("ATH-002", 2, "Administrators using encoded", lambda: telemetry(procs=[
        _ps(f"powershell.exe -ExecutionPolicy Bypass -EncodedCommand {ENC}", "wsmprovhost.exe", user="adm_sarah")]), "fires"),
    Case("ATH-002", 3, "CI/CD agents", lambda: telemetry(procs=[
        _ps(f"powershell.exe -enc {ENC}", "Runner.Worker.exe", user="svc_ci")]), "fires"),
    # ---------------------------------------------------------------- ATH-003
    Case("ATH-003", 0, "PowerShell installing modules", lambda: telemetry(
        procs=[_ps("powershell.exe Install-Module Az -Scope CurrentUser", "explorer.exe", pid=5001)],
        nets=[net("powershell.exe", "13.107.42.16", 443, pid=5001, url="https://www.powershellgallery.com/api/v2")]), "fires"),
    Case("ATH-003", 1, "Scripts calling cloud management", lambda: telemetry(
        procs=[_ps("powershell.exe -File C:\\Scripts\\rotate_keys.ps1", "explorer.exe", pid=5002)],
        nets=[net("powershell.exe", "52.94.236.248", 443, pid=5002, url="https://iam.amazonaws.com/")]), "fires"),
    Case("ATH-003", 2, "Package managers", lambda: telemetry(
        procs=[_ps("powershell.exe choco install 7zip -y", "cmd.exe", pid=5003)],
        nets=[net("powershell.exe", "104.16.66.114", 443, pid=5003, url="https://community.chocolatey.org/api/v2/")]), "fires"),
    Case("ATH-003", 3, "Telemetry, licensing", lambda: telemetry(
        procs=[_ps(r"powershell.exe -File C:\Program Files\Vendor\check_license.ps1", "VendorAgent.exe", pid=5004, user="SYSTEM")],
        nets=[net("powershell.exe", "52.114.128.10", 443, pid=5004, user="SYSTEM")]), "fires",
        "TEST-NET addresses are not public to is_public_ip; the vendor endpoint must be a routable one"),
    Case("ATH-003", 4, "Administrators running ad-hoc", lambda: telemetry(
        procs=[_ps("powershell.exe Invoke-WebRequest https://ifconfig.me", "explorer.exe", pid=5005, user="adm_sarah")],
        nets=[net("powershell.exe", "34.160.111.145", 443, pid=5005, user="adm_sarah")]), "fires"),
    # ---------------------------------------------------------------- ATH-004
    Case("ATH-004", 0, "IT support intentionally", lambda: telemetry(procs=[
        proc("procdump64.exe", r"procdump64.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp", "cmd.exe", user="adm_sarah")]), "fires"),
    Case("ATH-004", 1, "Endpoint security and DFIR", lambda: telemetry(procs=[
        proc("MsMpEng.exe", r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24\MsMpEng.exe"', "services.exe", user="SYSTEM")]), "silent",
        "the product reads LSASS memory through a handle, which command lines never show; the rule is blind here by construction"),
    Case("ATH-004", 2, "Performance or crash-dump", lambda: telemetry(procs=[
        proc("WerFault.exe", r"C:\Windows\System32\WerFault.exe -u -p 5120 -s 1234", "svchost.exe", user="SYSTEM")]), "silent"),
    Case("ATH-004", 3, "Security testing", lambda: telemetry(procs=[
        proc("rundll32.exe", r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\lsass.dmp full", "cmd.exe", user="redteam")]), "fires"),
    # ---------------------------------------------------------------- ATH-005
    Case("ATH-005", 0, "A service account with a stale", lambda: telemetry(
        logons=failures("svc_backup", "FS02", "10.10.20.40", 12)), "fires:not_high",
        "12 failures, no success: fires at MEDIUM since M15-3, when severity was made to follow the success condition"),
    Case("ATH-005", 1, "A user whose phone", lambda: telemetry(
        logons=failures("jdoe", "MAIL01", "10.10.30.7", 12) + [
            logon("jdoe", "MAIL01", logon_type=3, source_ip="10.10.30.7", when=at(5))]), "fires",
        "indistinguishable from guessing without the failure reason history; documented cost"),
    Case("ATH-005", 2, "Vulnerability scanners", lambda: telemetry(logons=[
        f for host in ("PC01", "PC02", "PC03", "PC04") for f in failures("svc_scan", host, "10.10.99.5", 4)]), "silent",
        "failures are grouped per device; a scanner spreads them thin"),
    Case("ATH-005", 3, "A misconfigured application", lambda: telemetry(
        logons=failures("svc_app", "SQL01", "10.10.20.55", 30, spacing_seconds=2)), "fires:not_high"),
    Case("ATH-005", 4, "Account lockout thresholds", lambda: telemetry(
        logons=failures("jdoe", "FS02", "10.10.20.15", 5) + [
            logon("jdoe", "FS02", logon_type=3, source_ip="10.10.20.15", action="failure",
                  failure_reason="account_locked", when=at(2))]), "silent"),
    # ---------------------------------------------------------------- ATH-006
    Case("ATH-006", 0, "Jump boxes", lambda: telemetry(logons=[
        logon(u, "JUMP01", logon_type=10, source_ip=f"10.10.30.{i}", source_device=f"PC0{i}", when=at(-60 + i))
        for i, u in enumerate(("adm_a", "adm_b", "adm_c"), start=1)] + [
        logon(u, "SRV01", logon_type=3, source_ip="10.10.20.9", source_device="JUMP01", when=at(i))
        for i, u in enumerate(("adm_a", "adm_b", "adm_c"), start=1)]), "silent",
        "each admin has an RDP session on the jump box, so they own it for the window"),
    Case("ATH-006", 1, "Shared or kiosk machines", lambda: telemetry(logons=[
        logon(u, "KIOSK01", logon_type=2, when=at(-30 + i)) for i, u in enumerate(("nurse_a", "nurse_b"), start=1)] + [
        logon(u, "FS02", logon_type=3, source_ip="10.10.40.3", source_device="KIOSK01", when=at(i))
        for i, u in enumerate(("nurse_a", "nurse_b"), start=1)]), "silent"),
    Case("ATH-006", 2, "'runas /netonly'", lambda: telemetry(logons=[
        logon("jdoe", "PC01", logon_type=2, when=at(-30)),
        logon("adm_jdoe", "PC01", logon_type=9, when=at(-1)),
        logon("adm_jdoe", "DC01", logon_type=3, source_ip="10.10.20.15", source_device="PC01", when=at(0))]), "fires",
        "the alternate credential has no session of its own on PC01; documented cost"),
    Case("ATH-006", 3, "Scheduled tasks or agents", lambda: telemetry(logons=[
        logon("jdoe", "PC01", logon_type=2, when=at(-30)),
        logon("svc_inventory", "PC01", logon_type=4, when=at(-1)),
        logon("svc_inventory", "FS02", logon_type=3, source_ip="10.10.20.15", source_device="PC01", when=at(0))]), "fires"),
    Case("ATH-006", 4, "A genuinely new employee", lambda: telemetry(logons=[
        logon("jdoe", "PC01", logon_type=2, when=at(-30)),
        logon("newhire", "FS02", logon_type=3, source_ip="10.10.20.15", source_device="PC01", when=at(0))]), "fires"),
    # ---------------------------------------------------------------- ATH-007
    Case("ATH-007", 0, "IT administrators legitimately using PsExec", lambda: telemetry(procs=[
        proc("PSEXESVC.exe", r"C:\Windows\PSEXESVC.exe", "services.exe", user="SYSTEM", device="FS02"),
        proc("cmd.exe", r"cmd.exe /Q /c ipconfig /all 1> \\127.0.0.1\ADMIN$\__1234 2>&1", "services.exe", user="adm_sarah", device="FS02")]), "fires"),
    Case("ATH-007", 1, "Monitoring, backup or deployment agents", lambda: telemetry(procs=[
        _ps(r"powershell.exe -NoProfile -File C:\Program Files\MonAgent\collect.ps1", "services.exe", user="SYSTEM", device="FS02")]), "fires"),
    Case("ATH-007", 2, "Scheduled maintenance jobs", lambda: telemetry(procs=[
        proc("cmd.exe", r"cmd.exe /c C:\Maint\nightly_cleanup.bat", "services.exe", user="SYSTEM", device="FS02")]), "fires"),
    Case("ATH-007", 3, "Vulnerability scanners performing", lambda: telemetry(procs=[
        proc("cmd.exe", r"cmd.exe /c wmic qfe list 1> \\127.0.0.1\ADMIN$\scan_9f2.txt", "services.exe", user="svc_scan", device="FS02")]), "fires"),
    # ---------------------------------------------------------------- ATH-008
    Case("ATH-008", 0, "Legitimate backup jobs", lambda: telemetry(procs=[
        proc("7z.exe", r'"C:\Program Files\7-Zip\7z.exe" a -t7z D:\Backups\finance-2026-09-01.7z D:\Finance\*', "BackupAgent.exe", user="svc_backup", device="FS02")]), "fires",
        "a wildcard source is enough for the rule whatever the destination; backup jobs fire at MEDIUM"),
    Case("ATH-008", 1, "Users compressing a folder", lambda: telemetry(procs=[
        _ps(r"powershell.exe Compress-Archive -Path C:\Users\jdoe\Pictures\Trip\* -DestinationPath C:\Users\jdoe\Desktop\trip.zip", "explorer.exe")]), "fires",
        "same: the wildcard source, not the staging path, decides; documented cost"),
    Case("ATH-008", 2, "Log rotation and diagnostic", lambda: telemetry(procs=[
        proc("tar.exe", r"tar.exe -a -cf C:\Windows\Temp\diag\bundle-20260901.zip C:\ProgramData\Vendor\Logs\*", "VendorSupport.exe", user="SYSTEM")]), "fires"),
    Case("ATH-008", 3, "Software build and packaging", lambda: telemetry(procs=[
        proc("7z.exe", r"7z.exe a C:\Users\svc_ci\AppData\Local\Temp\build-771\artifact.zip C:\agent\_work\1\s\dist\*", "Runner.Worker.exe", user="svc_ci")]), "fires"),
    # ---------------------------------------------------------------- ATH-009
    Case("ATH-009", 0, "Legitimate business documents", lambda: telemetry(procs=_office_env() + [
        proc("EXCEL.EXE", r'"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE" /dde "C:\Users\jdoe\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\ABCD\Budget_template.xlsm"', "OUTLOOK.EXE")]), "fires"),
    Case("ATH-009", 1, "Internal mail-merge", lambda: telemetry(procs=_office_env() + [
        proc("WINWORD.EXE", r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\jdoe\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\ABCD\Payslip_merge.docm"', "OUTLOOK.EXE")]), "fires"),
    # ---------------------------------------------------------------- ATH-010
    Case("ATH-010", 0, "IT support running a single", lambda: telemetry(procs=[
        proc("cmd.exe", "cmd.exe", "explorer.exe", pid=6100, user="adm_sarah"),
        proc("ipconfig.exe", "ipconfig /all", "cmd.exe", ppid=6100, user="adm_sarah")]), "silent"),
    Case("ATH-010", 1, "Automated inventory or compliance", lambda: telemetry(procs=[
        proc("cmd.exe", r"cmd.exe /c C:\Windows\CCM\SystemTemp\inventory.cmd", "CcmExec.exe", pid=6200, user="SYSTEM"),
        proc("whoami.exe", "whoami /all", "cmd.exe", ppid=6200, user="SYSTEM", when=at(0, 5)),
        proc("ipconfig.exe", "ipconfig /all", "cmd.exe", ppid=6200, user="SYSTEM", when=at(0, 10)),
        proc("systeminfo.exe", "systeminfo", "cmd.exe", ppid=6200, user="SYSTEM", when=at(0, 15))]), "fires"),
    Case("ATH-010", 2, "A single administrator manually", lambda: telemetry(procs=[
        proc("cmd.exe", "cmd.exe", "explorer.exe", pid=6300, user="adm_sarah"),
        proc("ipconfig.exe", "ipconfig /all", "cmd.exe", ppid=6300, user="adm_sarah", when=at(1)),
        proc("net.exe", "net user /domain", "cmd.exe", ppid=6300, user="adm_sarah", when=at(2)),
        proc("whoami.exe", "whoami /groups", "cmd.exe", ppid=6300, user="adm_sarah", when=at(3))]), "fires"),
    # ---------------------------------------------------------------- ATH-011
    Case("ATH-011", 0, "Backup software legitimately rotating", lambda: telemetry(procs=[
        proc("vssadmin.exe", "vssadmin delete shadows /for=D: /oldest /quiet", "BackupAgent.exe", user="svc_backup", device="FS02")]), "fires"),
    Case("ATH-011", 1, "An administrator clearing space", lambda: telemetry(procs=[
        proc("vssadmin.exe", "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=10%", "cmd.exe", user="adm_sarah")]), "silent"),
    Case("ATH-011", 2, "Disk imaging or migration", lambda: telemetry(procs=[
        proc("bcdedit.exe", "bcdedit /set {default} device partition=C:", "ImagingTool.exe", user="SYSTEM")]), "silent"),
    Case("ATH-011", 3, "Note that read-only enumeration", lambda: telemetry(procs=[
        proc("vssadmin.exe", "vssadmin list shadows", "cmd.exe", user="adm_sarah")]), "silent"),
    # ---------------------------------------------------------------- ATH-012
    Case("ATH-012", 0, "An administrator disabling real-time", lambda: telemetry(procs=[
        _ps("powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true", "explorer.exe", user="adm_sarah")]), "fires"),
    Case("ATH-012", 1, "Exclusions added", lambda: telemetry(procs=[
        _ps(r'powershell.exe Add-MpPreference -ExclusionPath "C:\Program Files\Contoso ERP"', "explorer.exe", user="adm_sarah")]), "fires"),
    Case("ATH-012", 2, "Endpoint agent upgrades", lambda: telemetry(procs=[
        proc("sc.exe", "sc stop SentinelAgent", "msiexec.exe", user="SYSTEM")]), "fires"),
    Case("ATH-012", 3, "Security products restarting", lambda: telemetry(procs=[
        proc("MpCmdRun.exe", r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24\MpCmdRun.exe" -SignatureUpdate', "MsMpEng.exe", user="SYSTEM")]), "silent"),
    # ---------------------------------------------------------------- AWS-001
    Case("AWS-001", 0, "Routine onboarding", lambda: telemetry(ctrls=[
        ctrl("ops_bob", "attach", "iam:user-policy", "new_dev", target_actor="new_dev", role_ref="arn:aws:iam::aws:policy/PowerUserAccess", device="aws:123/us-east-1", source="cloudtrail_mgmt"),
        ctrl("new_dev", "create", "iam:access-key", "new_dev", target_actor="new_dev", device="aws:123/us-east-1", source="cloudtrail_mgmt", when=at(2))]), "fires",
        "the newly granted identity creates its own first key: exactly the chain the rule describes"),
    Case("AWS-001", 1, "Infrastructure-as-code pipelines", lambda: telemetry(ctrls=[
        ctrl("terraform-apply", "attach", "iam:user-policy", "svc_deploy", target_actor="svc_deploy", role_ref="arn:aws:iam::123:policy/deploy", device="aws:123/us-east-1", source="cloudtrail_mgmt"),
        ctrl("terraform-apply", "create", "iam:access-key", "svc_deploy", target_actor="svc_deploy", device="aws:123/us-east-1", source="cloudtrail_mgmt", when=at(0, 30))]), "silent",
        "the rule keys on the *grantee* acting after the grant; a pipeline acting on its behalf never matches, so this declared false positive cannot trip the rule"),
    # ---------------------------------------------------------------- AWS-002
    Case("AWS-002", 0, "A deliberate, change-managed", lambda: telemetry(ctrls=[
        ctrl("ops_bob", "delete", "cloudtrail:trail", "legacy-trail", device="aws:123/us-east-1", source="cloudtrail_mgmt")]), "fires"),
    # ---------------------------------------------------------------- K8S-001
    Case("K8S-001", 0, "Legitimate cluster bootstrap", lambda: telemetry(ctrls=[
        ctrl("kubecfg", "create", "clusterrolebindings", "cluster-admin", target_actor="system:masters", role_ref="cluster-admin")]),
        "fires:target_silent", "measured on Kubernetes CI: 2,070 findings/day; M15-3 says K8S-001 needs a prevalence term"),
    # ---------------------------------------------------------------- K8S-002
    Case("K8S-002", 0, "A platform-team break-glass", lambda: telemetry(ctrls=[
        ctrl("sre-oncall", "create", "clusterrolebindings", "breakglass", target_actor="sre-oncall", role_ref="cluster-admin"),
        ctrl("sre-oncall", "exec", "pods/exec", "api-7f9", namespace="prod", when=at(4))]), "fires"),
)

_BY_KEY = {(c.rule_id, c.index): c for c in FP_CASES}


def test_every_declared_false_positive_has_a_case() -> None:
    """A rule may not document a false positive it does not test, and the sentence may
    not drift away from the case written for it."""
    missing, drifted = [], []
    for det in all_detectors():
        for index, sentence in enumerate(det.false_positives):
            case = _BY_KEY.get((det.rule_id, index))
            if case is None:
                missing.append(f"{det.rule_id}[{index}]: {sentence[:60]}")
            elif not sentence.startswith(case.opening):
                drifted.append(f"{det.rule_id}[{index}] now reads {sentence[:50]!r}, case covers {case.opening!r}")
    assert not missing, "declared false positives with no case:\n" + "\n".join(missing)
    assert not drifted, "sentences drifted from their cases:\n" + "\n".join(drifted)
    stale = [k for k in _BY_KEY if k[1] >= len(get_detector(k[0]).false_positives)]
    assert not stale, f"cases for false positives no longer declared: {stale}"


@pytest.mark.parametrize("case", FP_CASES, ids=[f"{c.rule_id}[{c.index}]" for c in FP_CASES])
def test_declared_false_positive_behaves_as_pinned(case: Case) -> None:
    findings = get_detector(case.rule_id).run(case.build())
    if case.expect == "silent":
        assert findings == [], f"{case.rule_id}[{case.index}] fired on: {case.opening}"
    else:
        assert findings, f"{case.rule_id}[{case.index}] is pinned as firing on: {case.opening}"
        if case.expect == "fires:target_not_high":
            # Pin today's behaviour exactly, so the target test below is the only place
            # the intended behaviour is stated.
            assert all(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)
        elif case.expect == "fires:not_high":
            assert all(f.severity not in (Severity.HIGH, Severity.CRITICAL) for f in findings), (
                f"{case.rule_id}[{case.index}] is pinned as firing below HIGH on: {case.opening}"
            )


_TARGETS = [c for c in FP_CASES if c.expect.startswith("fires:target")]


@pytest.mark.parametrize("case", _TARGETS, ids=[f"{c.rule_id}[{c.index}]" for c in _TARGETS])
@pytest.mark.xfail(strict=True, reason="M15-3 detection precision: pinned as a defect by M14 measurement")
def test_target_behaviour_for_measured_defects(case: Case) -> None:
    """Strict xfail: the day a fix lands, this passes, the suite goes red, and the pinned
    expectation above is updated in the same change."""
    findings = get_detector(case.rule_id).run(case.build())
    if case.expect == "fires:target_silent":
        assert findings == []
    else:
        assert findings and all(f.severity not in (Severity.HIGH, Severity.CRITICAL) for f in findings)
