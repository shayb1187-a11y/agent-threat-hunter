"""The standard incident suite this project is measured against.

Three scenarios, chosen so that passing all three means something:

``INC-001`` **Windows intrusion.** The full labelled chain -- macro to credential
access to lateral movement to collection. Exercises every layer end to end and is the
scenario the detection set was built around, so a failure here is a regression rather
than a discovery.

``INC-002`` **Cloud credential stuffing.** AWS CloudTrail. Deliberately foreign
telemetry: no processes, no network flows, no Windows logon types. Tests whether
anything transfers, and its expectations are set to what *should* work rather than to
what would be nice -- the endpoint rules genuinely cannot apply here and are not
credited.

``INC-003`` **A quiet day.** The same Windows environment with every labelled malicious
event removed. Its success condition is **zero cases**. This is the scenario most
evaluation suites omit, and omitting it systematically rewards trigger-happy detection:
if the cost of a false alarm never enters the numbers, a rule set that alerts on
everything scores perfectly.

The benign scenario is derived by subtraction
----------------------------------------------
Rather than writing a second generator, ``INC-003`` removes the labelled events from
the real dataset. That keeps the benign background *identical* to ``INC-001``'s --
including the IT administrator's encoded-PowerShell look-alike -- so the two scenarios
differ in exactly one respect: whether the intrusion is present. Any alert in
``INC-003`` is therefore unambiguously a false positive, with no "different data"
explanation available.
"""

from __future__ import annotations

from pathlib import Path

from ath.evaluation.incidents import Incident
from ath.telemetry.loader import Telemetry, load_ground_truth, load_telemetry

# Techniques the Windows chain should assert. Deliberately excludes T1041
# (Exfiltration) and T1566 (Spearphishing): the telemetry never shows bytes leaving,
# and there is no email telemetry. Expecting them would be asking the system to
# overclaim, and would reward it for doing so.
WINDOWS_EXPECTED_TECHNIQUES: frozenset[str] = frozenset({
    "T1204.002",   # macro-enabled document opened
    "T1059.001",   # PowerShell
    "T1027.010",   # command obfuscation
    "T1105",       # ingress tool transfer
    "T1071.001",   # web protocols C2
    "T1003.001",   # LSASS memory
    "T1110.001",   # password guessing
    "T1078",       # valid accounts
    "T1021.002",   # SMB admin shares
    "T1569.002",   # service execution
    "T1560.001",   # archive via utility
    "T1033",       # system owner discovery
})


# Scenarios in ground truth that represent an actual attack. `benign_lookalike` is
# labelled precisely *because* it is not one -- it is the IT administrator's encoded
# PowerShell, present to make false-positive analysis real. Treating every labelled
# scenario as malicious is a measurement bug with two compounding effects: it inflates
# the recall denominator with events no rule should flag as an intrusion, and it makes
# the known false-positive case count as a true positive, so the harness reports zero
# noise while a real false alarm sits in the output.
MALICIOUS_SCENARIOS: frozenset[str] = frozenset({"intrusion", "ransomware_prep"})


def scenario_event_ids(data_dir: Path, scenarios: frozenset[str]) -> frozenset[str]:
    """Event ids belonging to the named ground-truth scenarios.

    Reads ground truth, which is permitted here and nowhere outside
    :mod:`ath.evaluation` -- an evaluation harness that could not see the answer key
    would not be an evaluation harness.
    """
    truth = load_ground_truth(data_dir)
    ids: set[str] = set()
    for name, scenario in truth.get("scenarios", {}).items():
        if name not in scenarios:
            continue
        for stage in scenario.get("stages", {}).values():
            ids.update(stage.get("event_ids", []))
    return frozenset(ids)


def malicious_event_ids(data_dir: Path) -> frozenset[str]:
    """Every event id that is part of an actual attack."""
    return scenario_event_ids(data_dir, MALICIOUS_SCENARIOS)


def _without(telemetry: Telemetry, event_ids: frozenset[str]) -> Telemetry:
    """The same telemetry with the given events removed."""
    return Telemetry(
        processes=telemetry.processes[~telemetry.processes["event_id"].isin(event_ids)],
        network=telemetry.network[~telemetry.network["event_id"].isin(event_ids)],
        logons=telemetry.logons[~telemetry.logons["event_id"].isin(event_ids)],
    )


def windows_intrusion(data_dir: Path) -> Incident:
    """INC-001: the full labelled Windows intrusion.

    Each attack scenario is measured against telemetry containing *only that attack*.
    The alternative -- one dataset carrying both intrusions -- makes every per-incident
    number ambiguous: findings from `ransomware_prep` would count as noise cases here
    despite being true positives for a different incident, and widening the recall
    denominator to cover both would have moved this baseline the moment a second
    scenario was added. Isolating them keeps a benchmark movement attributable to a
    change in the system rather than to a change in the dataset.
    """
    telemetry = _without(
        load_telemetry(data_dir),
        scenario_event_ids(data_dir, frozenset({"ransomware_prep"})),
    )
    return Incident(
        incident_id="INC-001",
        name="Windows macro-to-collection intrusion",
        description=(
            "Macro-enabled attachment opened from Outlook, hidden encoded PowerShell, "
            "C2 beaconing, LSASS access, discovery, credential reuse to a file server, "
            "and archive staging."
        ),
        telemetry=telemetry,
        malicious_event_ids=scenario_event_ids(data_dir, frozenset({"intrusion"})),
        expected_techniques=WINDOWS_EXPECTED_TECHNIQUES,
        must_conclude=(
            # The lineage that reframes everything else.
            "WINWORD.EXE",
            # The C2 destination, named.
            "185.220.101.47",
            # The account whose credentials were reused.
            "svc_backup",
            # The brute-force reading, which must be reached as an inference.
            "guessed",
        ),
        never_as_fact=(
            # The telemetry shows an archive created and, separately, an outbound
            # connection. It never shows the archive's bytes leaving. Stated as fact,
            # this is the overclaim the whole calibration layer exists to prevent.
            "exfiltrat",
            # No email telemetry exists, so delivery was never observed.
            "phishing email",
        ),
    )


def cloud_credential_stuffing(fixture_dir: Path) -> Incident:
    """INC-002: repeated failed console logins followed by success, in CloudTrail."""
    from ath.telemetry.cloudtrail_source import CloudTrailSource

    result = CloudTrailSource(fixture_dir).load()
    telemetry = Telemetry(
        processes=result.tables["process"],
        network=result.tables["network"],
        logons=result.tables["logon"],
    )
    # Everything the adapter kept for the attacker principal is part of the incident.
    logons = telemetry.logons
    attacker = logons[logons["source_ip"] == "203.0.113.42"]

    return Incident(
        incident_id="INC-002",
        name="Cloud credential stuffing (AWS CloudTrail)",
        description=(
            "Twelve failed AWS console logins for one IAM user from a single external "
            "address, followed by a successful login and role assumption."
        ),
        telemetry=telemetry,
        malicious_event_ids=frozenset(attacker["event_id"]),
        # Only what genuinely transfers. The endpoint techniques are not expected here
        # and crediting them would measure the fixture, not the system.
        expected_techniques=frozenset({"T1110.001", "T1078"}),
        must_conclude=("dev_alice", "203.0.113.42"),
        never_as_fact=("exfiltrat", "malware"),
    )


def ransomware_preparation(data_dir: Path) -> Incident:
    """INC-004: recovery inhibition and defence impairment on a third host.

    A separate scenario rather than extra stages on the existing chain, so INC-001's
    measured numbers stay comparable across the change and a benchmark movement can be
    attributed to the system rather than to the dataset.
    """
    telemetry = _without(
        load_telemetry(data_dir),
        scenario_event_ids(data_dir, frozenset({"intrusion"})),
    )
    return Incident(
        incident_id="INC-004",
        name="Ransomware preparation (recovery inhibition + defence impairment)",
        description=(
            "Defender real-time protection disabled, a staging directory excluded from "
            "scanning, the AV process killed, then shadow copies, the backup catalogue "
            "and boot-time recovery all destroyed."
        ),
        telemetry=telemetry,
        malicious_event_ids=scenario_event_ids(
            data_dir, frozenset({"ransomware_prep"})
        ),
        expected_techniques=frozenset({"T1490", "T1685"}),
        must_conclude=("PC03",),
        never_as_fact=("encrypted", "ransom"),
    )


def quiet_day(data_dir: Path) -> Incident:
    """INC-003: the same environment with the intrusion removed. Silence is success.

    Only the **intrusion** is removed. The IT administrator's encoded-PowerShell
    look-alike stays, because it is the entire point: an earlier version of this
    scenario stripped every labelled event, which deleted the decoy along with the
    attack and left a dataset nothing could fire on. It passed, and measured nothing.
    """
    telemetry = load_telemetry(data_dir)
    return Incident(
        incident_id="INC-003",
        name="Quiet day (no intrusion present)",
        description=(
            "The identical benign background -- including the IT administrator's "
            "encoded-PowerShell look-alike -- with the intrusion removed. Any case "
            "raised here is unambiguously a false positive."
        ),
        telemetry=_without(telemetry, malicious_event_ids(data_dir)),
        malicious_event_ids=frozenset(),
    )


def kubernetes_privilege_escalation(fixture_dir: Path) -> Incident:
    """INC-005: a service account is granted cluster-admin, then execs into a pod.

    Deliberately foreign telemetry, the same way INC-002 was for CloudTrail: no
    processes, no network flows, no Windows logon types -- only
    ``ath.schema.EVENT_CONTROL`` rows. K8S-001 and K8S-002 correlate into one case via
    the grant event they share as evidence (``shared_evidence``), so this incident
    reaches the investigation stage rather than stopping at correlation the way
    INC-002 originally did.

    As of Milestone 13 Phase A, this incident is expected to **fail** its success
    condition, and that is the point being measured rather than a bug to route around:
    `run_incident` investigates with `default_specialists()`, the fixed roster that
    predates this milestone and does not include `ControlPlaneAgent` -- so the case is
    detected and correlated correctly, and then investigated by four specialists none
    of which read `ath.schema.EVENT_CONTROL`, producing zero facts. That is exactly the
    INC-002 zero-facts shape Milestone 11 fixed for a *missing case*, reappearing here
    for a *missing specialist* instead. Phase B threads environment-driven crew
    assembly through the orchestrator, and this incident is expected to pass from
    that point on -- see tests/test_incidents.py for the assertion of both states.
    """
    from ath.telemetry.k8s_audit_source import K8sAuditSource

    result = K8sAuditSource(fixture_dir, cluster="test-cluster").load()
    telemetry = Telemetry(
        processes=result.tables["process"], network=result.tables["network"],
        logons=result.tables["logon"], controls=result.tables["control"],
    )
    controls = telemetry.controls
    escalation = controls[
        (controls["actor"] == "system:serviceaccount:ci:ci-deployer")
        | (controls["actor"] == "system:serviceaccount:ci:ci-runner")
    ]

    return Incident(
        incident_id="INC-005",
        name="Kubernetes privilege escalation (RBAC grant then pod exec)",
        description=(
            "A CI deployer service account grants itself-adjacent cluster-admin to a "
            "second service account via a ClusterRoleBinding, which then execs into a "
            "production pod shortly after."
        ),
        telemetry=telemetry,
        malicious_event_ids=frozenset(escalation["event_id"]),
        expected_techniques=frozenset({"T1098.006", "T1609"}),
        must_conclude=("ci-runner", "cluster-admin", "web-1"),
        never_as_fact=("exfiltrat", "ransom"),
    )


def standard_suite(
    data_dir: Path, cloudtrail_dir: Path | None = None, k8s_audit_dir: Path | None = None,
) -> list[Incident]:
    """The incidents this project reports itself against."""
    incidents = [
        windows_intrusion(data_dir),
        ransomware_preparation(data_dir),
        quiet_day(data_dir),
    ]
    if cloudtrail_dir is not None and cloudtrail_dir.exists():
        incidents.insert(1, cloud_credential_stuffing(cloudtrail_dir))
    if k8s_audit_dir is not None and k8s_audit_dir.exists():
        incidents.insert(2, kubernetes_privilege_escalation(k8s_audit_dir))
    return incidents
