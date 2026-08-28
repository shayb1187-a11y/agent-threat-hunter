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
MALICIOUS_SCENARIOS: frozenset[str] = frozenset({"intrusion"})


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
    """INC-001: the full labelled Windows intrusion."""
    telemetry = load_telemetry(data_dir)
    return Incident(
        incident_id="INC-001",
        name="Windows macro-to-collection intrusion",
        description=(
            "Macro-enabled attachment opened from Outlook, hidden encoded PowerShell, "
            "C2 beaconing, LSASS access, discovery, credential reuse to a file server, "
            "and archive staging."
        ),
        telemetry=telemetry,
        malicious_event_ids=malicious_event_ids(data_dir),
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


def standard_suite(data_dir: Path, cloudtrail_dir: Path | None = None) -> list[Incident]:
    """The three incidents this project reports itself against."""
    incidents = [windows_intrusion(data_dir), quiet_day(data_dir)]
    if cloudtrail_dir is not None and cloudtrail_dir.exists():
        incidents.insert(1, cloud_credential_stuffing(cloudtrail_dir))
    return incidents
