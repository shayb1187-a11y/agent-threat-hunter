"""Tests for environment understanding, visibility, and coverage.

The load-bearing claims this milestone makes, and which these tests exist to hold:

1. Host roles come from *behaviour*, not from hostnames. Tested by renaming every
   host and asserting the roles are unchanged.
2. An absent telemetry channel is reported as absent rather than as "nothing found".
3. A sparsely populated channel is distinguished from a fully populated one, because
   a rule reading it will run and look healthy while seeing almost nothing.
4. Coverage separates "no rule" from "no telemetry" -- different problems, different
   remedies.
5. The analysis cannot silently drift from the rule set it describes.
"""

from __future__ import annotations

import pandas as pd
import pytest

from ath.environment import (
    CHANNEL_SPECS,
    DEGRADED_BELOW,
    FIELD_TO_CHANNEL,
    TECHNIQUE_WATCHLIST,
    UNUSABLE_BELOW,
    ChannelState,
    CoverageState,
    RuleSupport,
    RuleVerdict,
    TelemetryChannel,
    assess_channels,
    assess_coverage,
    build_environment_model,
)
from ath.hunting.base import all_detectors
from ath.mitre.attack import TECHNIQUES
from ath.schema import CORE_COLUMNS, TABLE_COLUMNS
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import Telemetry, load_telemetry

from tests import _builders as build


@pytest.fixture(scope="module")
def telemetry(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("env_data")
    write_telemetry(tables, gt, out)
    return load_telemetry(out)


@pytest.fixture(scope="module")
def environment(telemetry):
    return build_environment_model(telemetry)


@pytest.fixture(scope="module")
def coverage(environment):
    return assess_coverage(environment)


# ======================================================================================
# Environment model
# ======================================================================================


def test_platform_is_inferred_with_stated_evidence(environment) -> None:
    assert environment.platform == "windows"
    assert environment.platform_reason, "a platform claim must carry its basis"


def test_hosts_and_identities_are_discovered(environment) -> None:
    assert len(environment.hosts) >= 5
    assert len(environment.identities) >= 5
    assert environment.servers, "no host was classified as a server"
    assert environment.workstations, "no host was classified as a workstation"


def test_every_host_role_carries_a_reason(environment) -> None:
    """An unexplained classification cannot be checked, so it must not exist."""
    for host in environment.hosts.values():
        assert host.role_reason, f"{host.name} has a role with no stated basis"


def test_host_roles_survive_renaming_every_host(telemetry) -> None:
    """Roles must come from behaviour, not from naming conventions.

    ``FS02`` looks like a file server and this dataset agrees -- which is exactly why
    the inference has to be tested against names that carry no such hint. If roles
    were derived from naming, this test would collapse them all to unknown.
    """
    baseline = build_environment_model(telemetry)
    original_names = sorted(baseline.hosts)
    scrambled = {name: f"NODE{i:03d}" for i, name in enumerate(original_names)}

    def rename(df: pd.DataFrame) -> pd.DataFrame:
        out = df.copy()
        out["device"] = out["device"].map(lambda d: scrambled.get(d, d))
        if "source_device" in out.columns:
            out["source_device"] = out["source_device"].map(
                lambda d: scrambled.get(d, d) if d else d
            )
        return out

    renamed = build_environment_model(Telemetry(
        processes=rename(telemetry.processes),
        network=rename(telemetry.network),
        logons=rename(telemetry.logons),
    ))

    for original in original_names:
        assert renamed.hosts[scrambled[original]].role == baseline.hosts[original].role, (
            f"role of {original} changed when it was renamed -- the classification is "
            "reading the hostname, not the behaviour"
        )


def test_service_accounts_are_identified_from_logon_type(environment) -> None:
    names = {i.name for i in environment.service_accounts}
    assert "svc_backup" in names
    for identity in environment.service_accounts:
        assert identity.kind_reason


def test_privilege_signals_stay_selective(environment) -> None:
    """A signal that fires on almost everyone has stopped carrying information.

    An earlier version of this heuristic flagged accounts reaching >= 3 hosts, which
    marked 7 of 8 accounts here -- every user reaches the shared file and app
    servers. That is the same failure ATH-006 was written to avoid, so the threshold
    is now relative to the environment's own median rather than absolute.
    """
    flagged = environment.privileged_identities
    assert flagged, "no privilege signal at all would be equally useless"
    assert len(flagged) < len(environment.identities) / 2, (
        f"{len(flagged)} of {len(environment.identities)} accounts flagged as "
        "privileged -- the signal is not discriminating"
    )


def test_admin_share_use_is_a_privilege_signal(environment) -> None:
    """The strongest available signal: admin-share access requires local admin."""
    svc_backup = environment.identities["svc_backup"]
    assert any("administrative share" in s for s in svc_backup.privileged_signals)


def test_existing_security_controls_are_detected(environment) -> None:
    """A capability plan should not propose building what is already present."""
    products = set(environment.security_controls.values())
    assert any("Defender" in p for p in products)


def test_model_is_deterministic(telemetry) -> None:
    """Same telemetry in, same model out -- this is ground truth for later reasoning."""
    assert build_environment_model(telemetry).to_dict() == (
        build_environment_model(telemetry).to_dict()
    )


def test_model_serialises_to_json(environment) -> None:
    import json

    payload = json.loads(json.dumps(environment.to_dict()))
    assert payload["platform"] == "windows"
    assert payload["hosts"] and payload["channels"]


# ======================================================================================
# What the model refuses to guess
# ======================================================================================


def test_undetermined_is_populated(environment) -> None:
    """Listing only what was found reads as completeness. It is not."""
    assert environment.undetermined


def test_asset_criticality_is_never_inferred(environment) -> None:
    """Which assets matter is a business fact; no event data reveals it."""
    joined = " ".join(environment.undetermined).lower()
    assert "criticality" in joined


def test_short_window_is_flagged_as_no_baseline(environment) -> None:
    """Four hours cannot establish what is normal, and the model must say so."""
    assert environment.observation_hours < 168
    assert any("baseline" in u.lower() for u in environment.undetermined)


# ======================================================================================
# Telemetry channels
# ======================================================================================


def test_available_channels_are_recognised(environment) -> None:
    for channel in (
        TelemetryChannel.PROCESS_EXECUTION,
        TelemetryChannel.PROCESS_COMMAND_LINE,
        TelemetryChannel.AUTHENTICATION,
        TelemetryChannel.NETWORK_FLOW,
    ):
        assert environment.channels[channel].state is ChannelState.AVAILABLE


def test_channels_the_schema_cannot_carry_are_distinguished(environment) -> None:
    """`absent_by_schema` and `absent_in_data` need different remedies.

    One is a code change, the other an onboarding change. Reporting both as simply
    "missing" would make the coverage report unactionable.
    """
    assert environment.channels[TelemetryChannel.DNS_QUERY].state is (
        ChannelState.ABSENT_BY_SCHEMA
    )
    assert environment.channels[TelemetryChannel.NETWORK_INBOUND].state is (
        ChannelState.ABSENT_IN_DATA
    )


def test_inbound_visibility_is_measured_by_value_not_column_presence(environment) -> None:
    """The regression this measurement style exists to prevent.

    ``direction`` is populated on every network row, so counting non-empty cells
    would report inbound network visibility as 100% available -- while the dataset
    contains only outbound flows and inbound attack surface is entirely unobserved.
    """
    assessment = environment.channels[TelemetryChannel.NETWORK_INBOUND]
    assert assessment.state is ChannelState.ABSENT_IN_DATA
    assert assessment.populated_rows == 0


def test_sparse_channel_is_partial_not_available(environment) -> None:
    """A field populated on 0.5% of rows must not read as present.

    This is the failure mode the whole module exists for: a rule reading it runs,
    finds nothing, and is indistinguishable from a rule finding nothing because
    nothing happened.
    """
    assessment = environment.channels[TelemetryChannel.NETWORK_URL]
    assert assessment.state is ChannelState.PARTIAL
    assert 0 < assessment.coverage < 0.5


def test_every_absent_channel_says_how_to_close_the_gap(environment) -> None:
    """'You lack DNS telemetry' is only actionable with 'onboard resolver logs'."""
    for assessment in environment.channels.values():
        if not assessment.state.observable:
            assert assessment.spec.closes_gap_by, (
                f"{assessment.channel.value} is absent with no stated remedy"
            )


# ======================================================================================
# Coverage
# ======================================================================================


def test_all_four_states_are_reachable(coverage) -> None:
    """A split that only ever produces two states is not a four-way split."""
    counts = coverage.counts
    assert counts["detectable"] > 0
    assert counts["observable_undetected"] > 0
    assert counts["unobservable"] > 0


def test_covered_techniques_are_detectable(coverage) -> None:
    by_id = {t.technique_id: t for t in coverage.techniques}
    for technique_id in ("T1059.001", "T1110.001", "T1003.001"):
        assert by_id[technique_id].state is CoverageState.DETECTABLE
        assert by_id[technique_id].covering_rules


def test_missing_telemetry_dominates_missing_rules(coverage) -> None:
    """Unobservable is not a detection-engineering problem, and must not read as one."""
    by_id = {t.technique_id: t for t in coverage.techniques}
    dns = by_id["T1071.004"]
    assert dns.state is CoverageState.UNOBSERVABLE
    assert TelemetryChannel.DNS_QUERY in dns.missing_channels
    assert "onboard" in dns.state.remedy


def test_observable_undetected_names_a_real_gap(coverage) -> None:
    """These are the actionable ones: the data is present, the rule is not."""
    gaps = coverage.in_state(CoverageState.OBSERVABLE_UNDETECTED)
    assert gaps
    for gap in gaps:
        assert not gap.covering_rules, "a covered technique cannot be undetected"
        assert not gap.missing_channels, "an unobservable technique is not merely undetected"


def test_degraded_rule_does_not_invalidate_its_technique(coverage) -> None:
    """ATH-003 reads a sparse enrichment field but still detects on IP and port.

    Treating that as equivalent to missing core telemetry would report a working
    detection as broken -- and a reader who checks one false alarm stops reading the
    rest of the report.
    """
    by_id = {t.technique_id: t for t in coverage.techniques}
    web = by_id["T1071.001"]
    assert web.state is CoverageState.DETECTABLE
    assert "ATH-003" in web.degraded_rules, "the caveat must still be surfaced"


def test_ath003_is_degraded_not_unsupported(coverage) -> None:
    ath003 = next(r for r in coverage.rules if r.rule_id == "ATH-003")
    assert ath003.support is RuleSupport.DEGRADED
    assert ath003.runnable is True


def test_rules_with_full_telemetry_are_supported(coverage) -> None:
    supported = [r for r in coverage.rules if r.support is RuleSupport.SUPPORTED]
    assert len(supported) >= 8


# ======================================================================================
# Drift guards
# ======================================================================================


def test_every_rule_field_maps_to_a_channel_or_is_a_core_column() -> None:
    """A new rule's telemetry dependency must not be silently ignored.

    Runnability is computed by mapping `fields_used` through FIELD_TO_CHANNEL -- unless
    a rule declares `channels` explicitly, which exists precisely because column-name
    inference cannot disambiguate two telemetry sources that share a column vocabulary
    (AWS management events and Kubernetes audit events both have a `verb`/
    `resource_type` on ath.schema.EVENT_CONTROL). Those rules are correctly exempt from
    this check -- coverage.py._channels_for_rule reads their explicit declaration
    instead, never FIELD_TO_CHANNEL, so an unmapped field there carries no risk of the
    silent "reported as fully supported" failure this test guards against.
    """
    core = set(CORE_COLUMNS) | {"timestamp", "event_id"}
    unmapped: set[str] = set()
    for detector in all_detectors():
        if detector.channels:
            continue
        for field in detector.fields_used:
            if field not in FIELD_TO_CHANNEL and field not in core:
                unmapped.add(f"{detector.rule_id}:{field}")
    assert not unmapped, (
        f"fields with no channel mapping: {sorted(unmapped)}. Add them to "
        "FIELD_TO_CHANNEL, to the core columns if they carry no requirement, or "
        "declare Detector.channels explicitly if column-name inference is ambiguous."
    )


def test_watchlist_agrees_with_the_attack_catalogue() -> None:
    """Where the two overlap they must not drift apart.

    The watchlist is deliberately broader than the ATT&CK catalogue -- it must be
    able to name techniques this project cannot evidence, or it could never report a
    blind spot. But any id present in both has to mean the same thing in both.
    """
    for entry in TECHNIQUE_WATCHLIST:
        canonical = TECHNIQUES.get(entry.technique_id)
        if canonical is None:
            continue
        assert entry.name == canonical.name, (
            f"{entry.technique_id} is '{entry.name}' in the watchlist but "
            f"'{canonical.name}' in the ATT&CK catalogue"
        )


def test_watchlist_ids_are_unique() -> None:
    ids = [e.technique_id for e in TECHNIQUE_WATCHLIST]
    assert len(ids) == len(set(ids))


def test_every_channel_has_exactly_one_spec() -> None:
    """Every declared channel must be assessable, or coverage would KeyError."""
    specced = {spec.channel for spec in CHANNEL_SPECS}
    assert specced == set(TelemetryChannel)


def test_every_watchlist_channel_is_a_known_channel() -> None:
    for entry in TECHNIQUE_WATCHLIST:
        assert entry.required_channels, f"{entry.technique_id} requires no telemetry"
        for channel in entry.required_channels:
            assert channel in set(TelemetryChannel)


# ======================================================================================
# Two environments, two assessments
#
# The claim the whole milestone rests on: the same analysis, given different
# environments, must produce different pictures of what is defensible. If it produced
# the same posture regardless of input, it would be a static document with extra steps.
# ======================================================================================


@pytest.fixture(scope="module")
def defender_environment():
    """An environment built from the Defender import path rather than the generator."""
    from pathlib import Path

    from ath.telemetry import DefenderExportSource

    fixture = Path(__file__).parent / "fixtures" / "defender_export"
    result = DefenderExportSource(fixture).load()
    return build_environment_model(Telemetry(
        processes=result.tables["process"],
        network=result.tables["network"],
        logons=result.tables["logon"],
    ))


def test_environment_model_works_on_an_imported_export(defender_environment) -> None:
    """The analysis is written against the canonical schema, not against one source."""
    assert defender_environment.data_sources == ("defender_export",)
    assert defender_environment.hosts
    assert defender_environment.platform == "windows"


@pytest.fixture(scope="module")
def cloudtrail_environment():
    """An environment built from AWS CloudTrail -- genuinely different telemetry."""
    from pathlib import Path

    from ath.telemetry.cloudtrail_source import CloudTrailSource

    fixture = Path(__file__).parent / "fixtures" / "cloudtrail"
    result = CloudTrailSource(fixture).load()
    return build_environment_model(Telemetry(
        processes=result.tables["process"],
        network=result.tables["network"],
        logons=result.tables["logon"],
    ))


def test_similar_telemetry_yields_a_similar_posture(environment, defender_environment) -> None:
    """Two Windows endpoint sources assess the same *at channel granularity*.

    This started as a "two environments must differ" test and passed for the wrong
    reason: the Defender fixture records no `source_device`, and the channel model
    then wrongly declared source attribution absent. Fixing that made these two
    identical -- as they should be, since both carry the same *kinds* of telemetry.
    The model reads telemetry shape, not the source's name, and this pins that.

    The per-field measurement (M18) looked for a difference here and found one that was
    not real: the Defender fixture's single logon row is a *console* logon (type 2),
    which has no source host by definition, and the measurement read its empty
    `source_device` as ATH-006 being blind. It was not blind; it had no remote logon to
    be blind about. M18-4 made applicability part of the measurement, and the two
    postures agree at field granularity too.

    What is asserted instead is the shape of that agreement, which is stronger than the
    equality: on the generated corpus `source_device` is measured (238 remote logons)
    and populated, and on the Defender fixture it is reported not applicable rather than
    empty. Both halves must hold, so neither "applicability swallowed a real gap" nor
    "the console case came back as blindness" can pass unnoticed.
    """
    assert environment.available_channels == defender_environment.available_channels
    generated = assess_coverage(environment)
    imported = assess_coverage(defender_environment)

    assert (
        {r.rule_id: r.support for r in generated.rules}
        == {r.rule_id: r.support for r in imported.rules}
    ), "the same channels must yield the same channel-level support"

    differing = {
        r.rule_id for r in imported.rules
        if r.verdict is not next(g.verdict for g in generated.rules if g.rule_id == r.rule_id)
    }
    assert differing == set(), differing

    on_defender = next(r for r in imported.rules if r.rule_id == "ATH-006")
    assert on_defender.verdict is RuleVerdict.USABLE
    assert "source_device" in on_defender.not_applicable_fields
    assert "source_device" not in on_defender.unpopulated_fields

    on_generated = next(r for r in generated.rules if r.rule_id == "ATH-006")
    measured = {f.column: f for f in on_generated.fields}
    assert "source_device" not in on_generated.not_applicable_fields
    assert measured["source_device"].population.applicable_rows > 0
    assert measured["source_device"].fraction == 1.0


def test_different_telemetry_yields_a_different_posture(
    environment, cloudtrail_environment
) -> None:
    """The claim the whole design rests on, tested against genuinely foreign telemetry.

    CloudTrail is not a second Windows endpoint product -- it has no processes, no
    network flows, and no Windows logon types. If the same posture came back for it,
    the assessment would not be reading the environment at all.
    """
    windows = assess_coverage(environment).counts
    cloud = assess_coverage(cloudtrail_environment).counts

    assert environment.available_channels != cloudtrail_environment.available_channels
    assert windows != cloud
    assert cloud["unobservable"] > windows["unobservable"]
    assert cloud["detectable"] < windows["detectable"]


def test_cloud_environment_reports_endpoint_blindness(cloudtrail_environment) -> None:
    """Control-plane telemetry must not be mistaken for endpoint visibility."""
    for channel in (
        TelemetryChannel.PROCESS_EXECUTION,
        TelemetryChannel.PROCESS_COMMAND_LINE,
        TelemetryChannel.NETWORK_FLOW,
    ):
        assert not cloudtrail_environment.channels[channel].state.observable


def test_cloud_environment_recognises_its_own_channel(cloudtrail_environment) -> None:
    assert cloudtrail_environment.channels[
        TelemetryChannel.CLOUD_CONTROL_PLANE
    ].state.observable


def test_rules_that_cannot_work_on_cloud_telemetry_say_so(cloudtrail_environment) -> None:
    """Endpoint rules must be reported unsupported, not left looking healthy."""
    report = assess_coverage(cloudtrail_environment)
    unsupported = {r.rule_id for r in report.rules if not r.runnable}
    assert {"ATH-001", "ATH-002", "ATH-004"} <= unsupported


def test_visibility_model_agrees_with_what_actually_fires(cloudtrail_environment) -> None:
    """The contradiction this stress test caught, pinned so it cannot return.

    ATH-005 fires on CloudTrail and produces a CRITICAL finding. The channel model
    initially declared it "unsupported -- will run and find nothing regardless of what
    occurred", because source attribution was measured on `source_device` alone and
    CloudTrail records only `source_ip`. A visibility model that contradicts observed
    behaviour is worse than not having one: it tells an analyst to disbelieve a true
    alert.
    """
    from pathlib import Path

    from ath.hunting import run_hunt
    from ath.telemetry.cloudtrail_source import CloudTrailSource

    result = CloudTrailSource(
        Path(__file__).parent / "fixtures" / "cloudtrail"
    ).load()
    telemetry = Telemetry(
        processes=result.tables["process"],
        network=result.tables["network"],
        logons=result.tables["logon"],
    )
    fired = {f.rule_id for f in run_hunt(telemetry).findings}
    assert "ATH-005" in fired, "fixture no longer exercises the brute-force rule"

    supported = {r.rule_id for r in assess_coverage(cloudtrail_environment).rules
                 if r.runnable}
    assert fired <= supported, (
        f"rules {sorted(fired - supported)} produced findings while the visibility "
        "model reported them as unable to work"
    )


def test_coverage_gaps_are_explained_not_merely_counted(defender_environment) -> None:
    """Every gap must name the telemetry that would close it."""
    report = assess_coverage(defender_environment)
    for gap in report.in_state(CoverageState.UNOBSERVABLE):
        assert gap.missing_channels, f"{gap.technique_id} is unobservable for no stated reason"


# ======================================================================================
# Correctness: a field must mean what its name says
# ======================================================================================


def test_external_destinations_are_actually_external(environment) -> None:
    """`external_destinations` collected every remote IP, private ones included.

    A host mounting an internal file server appeared in a field named "external",
    which both overstates egress and buries real egress in noise. The regression is
    worth pinning because the failure is invisible: the list is populated and looks
    plausible either way.
    """
    from ath.hunting.indicators import is_public_ip

    saw_any = False
    for host in environment.hosts.values():
        for address in host.external_destinations:
            saw_any = True
            assert is_public_ip(address), (
                f"{host.name} lists private address {address} as an external destination"
            )
    assert saw_any, "no external destinations at all -- the test proves nothing"


def test_internal_peers_are_actually_internal(environment) -> None:
    from ath.hunting.indicators import is_public_ip

    for host in environment.hosts.values():
        for address in host.internal_peers:
            assert not is_public_ip(address), (
                f"{host.name} lists public address {address} as an internal peer"
            )


def test_internal_and_external_partition_all_destinations(environment, telemetry) -> None:
    """The split must lose nothing -- every contacted address lands in exactly one side."""
    for host in environment.hosts.values():
        rows = telemetry.network[telemetry.network["device"] == host.name]
        contacted = {ip for ip in rows["remote_ip"] if ip}
        classified = set(host.external_destinations) | set(host.internal_peers)
        assert classified == contacted, f"{host.name}: addresses lost or duplicated"
        assert not set(host.external_destinations) & set(host.internal_peers)


def test_environment_and_detection_agree_on_external(environment, telemetry) -> None:
    """One definition of "external" per system.

    The egress rule (ATH-003) and the environment model must not disagree about which
    addresses leave the network -- two definitions of that word is a bug waiting to be
    argued about in an incident.
    """
    from ath.hunting.indicators import is_public_ip

    for host in environment.hosts.values():
        rows = telemetry.network[telemetry.network["device"] == host.name]
        by_rule = {ip for ip in rows["remote_ip"] if ip and is_public_ip(ip)}
        assert set(host.external_destinations) == by_rule


# ======================================================================================
# Provenance
# ======================================================================================


def test_coverage_report_records_what_it_describes(coverage) -> None:
    """A posture verdict is meaningless without knowing what produced it.

    "8 of 25 techniques unobservable" says something very different about a four-hour
    synthetic sample than about a month of production telemetry. The investigation
    report already carries its data sources; the coverage report was the one output
    that could not say what it was about.
    """
    provenance = coverage.provenance
    assert provenance["data_sources"] == ["synthetic"]
    assert provenance["platform"] == "windows"
    assert provenance["event_count"] > 0
    assert provenance["observation_window"] is not None
    assert provenance["rules_assessed"] > 0
    assert provenance["techniques_assessed"] == len(coverage.techniques)


def test_coverage_provenance_survives_serialisation(coverage) -> None:
    import json

    payload = json.loads(json.dumps(coverage.to_dict()))
    assert payload["provenance"]["data_sources"] == ["synthetic"]


def test_coverage_provenance_tracks_the_actual_source(defender_environment) -> None:
    """Provenance must follow the telemetry, not be a constant."""
    report = assess_coverage(defender_environment)
    assert report.provenance["data_sources"] == ["defender_export"]


# ======================================================================================
# Per-field usability (M18): a rule is only as usable as the fields it filters on
#
# The defect these guard is the one the M17 external evaluation found on COMISET, and
# it is invisible to every measurement that came before them: `remote_ip` populated on
# 100% of 589,477 network rows, `remote_port`/`protocol`/`direction` populated on 1, the
# NETWORK_FLOW channel reported AVAILABLE, ATH-003 reported SUPPORTED, and ATH-003's
# zero findings read as clean data. Each test below is built so it fails if the
# field-level check is removed -- deleting it must not leave a green suite.
# ======================================================================================


def _rule(telemetry: Telemetry, rule_id: str):
    """The runnability verdict for one rule against one in-memory telemetry set."""
    report = assess_coverage(build_environment_model(telemetry))
    return next(r for r in report.rules if r.rule_id == rule_id)


def _blank(rows: list[dict], *columns: str, keep_first: int = 0) -> list[dict]:
    """Empty the named columns on every row but the first ``keep_first``.

    This is the M17-2 shape in one function: an adapter that inferred its field names
    from one sampled record, mapped that record correctly, and lost the attribute on
    every other row. Takes column names as data so the same helper reproduces the shape
    on the network, logon and control tables without a line of per-table code.
    """
    out = []
    for index, row in enumerate(rows):
        row = dict(row)
        if index >= keep_first:
            for column in columns:
                row[column] = None if column == "remote_port" else ""
        out.append(row)
    return out


def test_channel_view_calls_a_lost_attribute_available_and_the_field_view_does_not() -> None:
    """The M17-2 regression shape, both halves asserted.

    Fails without the field-level check: the channel measurement reports NETWORK_FLOW
    AVAILABLE (asserted here, deliberately, as proof the old measurement misses this),
    so ATH-003 would come back DEGRADED at worst and its zero findings would again be
    indistinguishable from clean data.
    """
    rows = [
        build.net("powershell.exe", "203.0.113.9", 443, device="PC07", user="aholt",
                  when=build.at(seconds=i), url="http://203.0.113.9/a")
        for i in range(250)
    ]
    telemetry = build.telemetry(
        # A process row so PROCESS_EXECUTION is available: the only thing wrong with
        # this dataset must be the three lost network attributes.
        procs=[build.proc("powershell.exe", "powershell.exe -c 1", "explorer.exe",
                          device="PC07", user="aholt")],
        nets=_blank(rows, "remote_port", "protocol", "direction", keep_first=1),
    )

    channels = assess_channels(telemetry)
    assert channels[TelemetryChannel.NETWORK_FLOW].state is ChannelState.AVAILABLE, (
        "the channel view is supposed to miss this -- if it no longer does, this test "
        "is not exercising the gap it was written for"
    )

    ath003 = _rule(telemetry, "ATH-003")
    assert ath003.verdict is RuleVerdict.UNUSABLE
    assert set(ath003.sparse_fields) == {"remote_port", "protocol", "direction"}
    assert set(ath003.unpopulated_fields) == {"remote_port", "direction"}
    for usability in ath003.fields:
        if usability.column in ath003.sparse_fields:
            assert usability.fraction == 1 / 250


def test_the_same_shape_on_the_logon_table_makes_its_rule_unusable() -> None:
    """Generalisation, table two: no rule-specific code, different values throughout.

    Fails without the field-level check: `unpopulated_fields` would be empty and
    nothing would name `action` as the lost column.
    """
    rows = [
        build.logon("rburke", "FS09", logon_type=3, source_ip="198.51.100.24",
                    source_device="WKS44", action="failure", failure_reason="bad_password",
                    when=build.at(seconds=i * 5))
        for i in range(220)
    ]
    telemetry = build.telemetry(logons=_blank(rows, "action", keep_first=1))

    ath005 = _rule(telemetry, "ATH-005")
    assert ath005.verdict is RuleVerdict.UNUSABLE
    assert ath005.unpopulated_fields == ("action",)
    assert "action" in ath005.detail and "220" in ath005.detail


def test_the_same_shape_on_the_control_table_makes_its_rule_unusable() -> None:
    """Generalisation, table three -- and the strongest of the three.

    The CLOUD_MANAGEMENT_ACTIVITY channel is AVAILABLE here (it is evidenced by the
    source value, which every row carries), so nothing but the field measurement can
    reach this verdict. Fails without the field-level check with AWS-002 reported
    USABLE while `resource_type` -- the column its filter compares -- is empty.
    """
    rows = [
        build.ctrl("svc-deployer", "stop", "cloudtrail:trail", "org-trail",
                   device="aws:222233334444/eu-west-1", source_ip="192.0.2.77",
                   source="cloudtrail_mgmt", when=build.at(seconds=i * 30))
        for i in range(240)
    ]
    telemetry = build.telemetry(ctrls=_blank(rows, "resource_type", keep_first=1))

    channels = assess_channels(telemetry)
    assert channels[TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY].state.usable

    aws002 = _rule(telemetry, "AWS-002")
    assert aws002.verdict is RuleVerdict.UNUSABLE
    assert aws002.unpopulated_fields == ("resource_type",)


def test_an_empty_declared_table_is_not_eligible_and_says_so_distinctly() -> None:
    """"No input" and "input I cannot read" are different facts with different remedies.

    Fails without the field-level check: there would be no NOT_ELIGIBLE state at all,
    and both cases would collapse into the channel view's single `unsupported`.
    """
    telemetry = build.telemetry(
        procs=[build.proc("whoami.exe", "whoami", "cmd.exe", device="PC11", user="mchan")],
    )

    eligible = _rule(telemetry, "ATH-004")
    starved = _rule(telemetry, "ATH-005")

    assert starved.verdict is RuleVerdict.NOT_ELIGIBLE
    assert starved.verdict is not RuleVerdict.UNUSABLE
    assert starved.to_dict()["verdict"] == "not_eligible"
    assert starved.to_dict()["tables"] == {"logon": 0}
    assert not starved.runnable
    assert starved.fields == (), "an empty table cannot have a measured field fraction"
    assert eligible.verdict is RuleVerdict.USABLE


def test_only_an_optional_field_sparse_is_degraded_not_unusable() -> None:
    """ATH-003 grades on `remote_url` and detects without it.

    Fails without the field-level check by never reaching DEGRADED for a field reason
    at all; fails with a check that ignores `optional_fields` by reporting a working
    rule UNUSABLE -- the error that spends a reader's trust for nothing.
    """
    rows = [
        build.net("cscript.exe", "203.0.113.40", 8080, device="PC21", user="tnadel",
                  when=build.at(seconds=i * 2))
        for i in range(200)
    ]
    telemetry = build.telemetry(
        procs=[build.proc("cscript.exe", "cscript x.vbs", "explorer.exe",
                          device="PC21", user="tnadel")],
        nets=rows,  # remote_url empty on every row; everything else populated
    )

    ath003 = _rule(telemetry, "ATH-003")
    assert ath003.verdict is RuleVerdict.DEGRADED
    assert ath003.sparse_fields == ("remote_url",)
    assert not ath003.unpopulated_fields
    assert ath003.runnable


def test_the_two_thresholds_are_boundaries_not_approximations() -> None:
    """Exactly at each threshold, and one row either side of it.

    Fails without the field-level check (no verdict moves at all), and fails if either
    comparison is written ``<=`` instead of ``<`` -- which would report a rule sitting
    exactly on the documented floor as blind.
    """
    def network(populated: int, total: int) -> Telemetry:
        rows = [
            build.net("wscript.exe", "203.0.113.77", 443, device="PC33", user="dgrey",
                      when=build.at(seconds=i), url="http://203.0.113.77/z")
            for i in range(total)
        ]
        return build.telemetry(
            procs=[build.proc("wscript.exe", "wscript a.js", "explorer.exe",
                              device="PC33", user="dgrey")],
            nets=_blank(rows, "direction", keep_first=populated),
        )

    assert UNUSABLE_BELOW == 0.01 and DEGRADED_BELOW == 0.5

    # exactly at the unusable floor: 2/200 == 0.01 -> not unusable
    at_floor = _rule(network(2, 200), "ATH-003")
    assert at_floor.verdict is RuleVerdict.DEGRADED
    assert at_floor.sparse_fields == ("direction",)

    # one row below it: 1/200 == 0.005 -> unusable
    below_floor = _rule(network(1, 200), "ATH-003")
    assert below_floor.verdict is RuleVerdict.UNUSABLE
    assert below_floor.unpopulated_fields == ("direction",)

    # exactly at the partial threshold: 100/200 == 0.5 -> not degraded
    at_partial = _rule(network(100, 200), "ATH-003")
    assert at_partial.verdict is RuleVerdict.USABLE
    assert not at_partial.sparse_fields

    # one row below it: 99/200 == 0.495 -> degraded
    below_partial = _rule(network(99, 200), "ATH-003")
    assert below_partial.verdict is RuleVerdict.DEGRADED
    assert below_partial.sparse_fields == ("direction",)


def test_every_rule_declares_tables_that_carry_the_fields_it_declares() -> None:
    """The static declaration check: a rule cannot be measured on a field it misfiled.

    Guards the drift that made this milestone necessary in both directions -- a rule
    declaring a field no declared table carries (measured as 0% forever, or silently
    skipped), and a rule declaring a table none of its fields belong to (counted as
    eligible input it never reads, which is exactly the stale ATH-007 entry in the M17
    script's hard-coded table map).

    Fails if a new rule omits `tables`, misspells a field, or lists an `optional_fields`
    entry that is not in `fields_used`.
    """
    core = set(CORE_COLUMNS)
    for detector in all_detectors():
        assert detector.tables, f"{detector.rule_id} declares no input table"
        for table in detector.tables:
            assert table in TABLE_COLUMNS, f"{detector.rule_id}: unknown table {table!r}"

        declared_columns = {c for t in detector.tables for c in TABLE_COLUMNS[t]}
        for name in detector.fields_used:
            if name in core:
                continue
            assert name in declared_columns, (
                f"{detector.rule_id} declares field {name!r}, which no table it "
                f"declares ({sorted(detector.tables)}) carries"
            )

        for table in detector.tables:
            specific = set(TABLE_COLUMNS[table]) - core
            assert specific & set(detector.fields_used), (
                f"{detector.rule_id} declares table {table!r} but reads none of its "
                "columns"
            )

        assert detector.optional_fields <= set(detector.fields_used), (
            f"{detector.rule_id}: optional_fields not a subset of fields_used"
        )


def test_the_verdict_logic_names_no_rule_table_or_field() -> None:
    """An anti-overfitting guard on the module that decides verdicts.

    The verdict must be computed from what detectors declare. A rule id, table name or
    column name appearing in the decision path would mean the measurement was tuned to
    the corpus that exposed the defect, and the next corpus would go unmeasured.
    """
    import inspect

    from ath.environment import coverage

    for function in (
        coverage.rule_field_usability, coverage._field_verdict, coverage._table_rows,
        coverage._gating_channels_for_rule,
    ):
        body = inspect.getsource(function)
        body = body.split('"""')[0] + body.split('"""')[-1]  # docstrings may cite cases
        for forbidden in ("ATH-", "AWS-", "K8S-", "remote_port", "remote_url",
                          "direction", "logon_type", "source_device"):
            assert forbidden not in body, (
                f"{function.__name__} names {forbidden!r}; the verdict must read only "
                "what detectors declare"
            )
