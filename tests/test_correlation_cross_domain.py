"""The generic cross-channel link that replaced the cross-domain rule-id allowlist.

``reports/m19b/necessity/AUDIT.md`` measured the defect these tests guard against: the
only structural signal able to put two specialist domains in one case was
``auth_then_exec``, gated by ``_AUTH_RULES = {ATH-005, ATH-006}`` and
``_REMOTE_EXEC_RULES = {ATH-007}``. No pair of rule ids outside that product could ever
produce a cross-domain case, whatever the telemetry contained -- so on flaws.cloud,
79,424 authentication rows and 1,857,154 control-plane rows produced 280 control-plane
cases, one identity case, and never a case containing both.

The tests come in matched pairs, like ``tests/test_correlation.py``'s: for every "these
two domains link" there is a "and these do not", because a predicate that only passes the
first half is indistinguishable from one that links everything to everything.
"""

from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

import pandas as pd
import pytest

from ath.channels import TelemetryChannel
from ath.correlation import CorrelationConfig, correlate
from ath.correlation import correlator as correlator_module
from ath.correlation.correlator import (
    CHANNEL_FAMILY,
    CHANNELS_WITHOUT_FAMILY,
    CROSS_DOMAIN_WINDOW,
    PRINCIPAL_COLUMNS,
    _CrossChannelIndex,
    _ProcessIndex,
    channel_families,
    score_pair,
)
from ath.evaluation.incidents import run_incident
from ath.evaluation.suite import standard_suite
from ath.hunting import Evidence, Finding, Severity
from ath.schema import TABLE_COLUMNS
from ath.telemetry.loader import Telemetry
from ath.telemetry.normalize import coerce_and_validate

START = pd.Timestamp("2026-08-17 09:00", tz="UTC")


# ======================================================================================
# Builders: telemetry rows carrying a principal, and findings that cite them
# ======================================================================================


def _frame(event_type: str, rows: list[dict]) -> pd.DataFrame:
    """Canonical telemetry, through the same coercion every adapter must pass."""
    return coerce_and_validate(
        pd.DataFrame(rows, columns=list(TABLE_COLUMNS[event_type])), event_type,
    )


def _telemetry(
    process: list[dict] = (),
    network: list[dict] = (),
    logons: list[dict] = (),
    controls: list[dict] = (),
) -> Telemetry:
    return Telemetry(
        processes=_frame("process", list(process)),
        network=_frame("network", list(network)),
        logons=_frame("logon", list(logons)),
        controls=_frame("control", list(controls)),
    )


def _row(event_type: str, event_id: str, minute: int, **fields) -> dict:
    row = {
        "event_id": event_id,
        "timestamp": START + timedelta(minutes=minute),
        "event_type": event_type,
        "device": "aws:111122223333/us-east-1",
        "user": "",
        "source": "test",
        "source_ref": "",
    }
    row.update(fields)
    return row


def _finding(
    rule_id: str,
    *,
    event_id: str,
    minute: int,
    device: str,
    user: str,
    channels: frozenset,
) -> Finding:
    """A finding that declares its channels, the way a rule with an explicit
    ``Detector.channels`` does -- so these tests exercise the family predicate rather
    than the rule catalogue."""
    return Finding(
        rule_id=rule_id,
        title="t",
        severity=Severity.HIGH,
        device=device,
        user=user,
        evidence=(Evidence(event_id, START + timedelta(minutes=minute), "s"),),
        reason="r",
        channels=channels,
    )


IDENTITY = frozenset({TelemetryChannel.AUTHENTICATION})
CONTROL = frozenset({TelemetryChannel.CLOUD_MANAGEMENT_ACTIVITY})
ENDPOINT = frozenset({TelemetryChannel.PROCESS_EXECUTION})
NETWORK = frozenset({TelemetryChannel.NETWORK_FLOW})


def _cloud_pair(gap_minutes: int, control_actor: str = "dev_alice"):
    """An identity finding and a control-plane finding, ``gap_minutes`` apart.

    This is the flaws.cloud shape the audit found unreachable: a CloudTrail
    authentication row and a CloudTrail management-API row naming one IAM principal.
    """
    telemetry = _telemetry(
        logons=[_row("logon", "evt-auth", 0, user="dev_alice", action="success")],
        controls=[
            _row(
                "control", "evt-ctl", gap_minutes,
                user=control_actor, actor=control_actor, target_actor="",
                verb="create", resource_type="iam:accesskey", decision="allowed",
            )
        ],
    )
    auth = _finding(
        "ATH-005", event_id="evt-auth", minute=0,
        device="aws:111122223333/us-east-1", user="dev_alice", channels=IDENTITY,
    )
    control = _finding(
        "AWS-002", event_id="evt-ctl", minute=gap_minutes,
        device="aws:111122223333/us-east-1", user=control_actor, channels=CONTROL,
    )
    return telemetry, auth, control


def _signals(a, b, telemetry, config=None):
    config = config or CorrelationConfig()
    index = _ProcessIndex(telemetry)
    cross = _CrossChannelIndex(telemetry, [a, b])
    return score_pair(a, b, index, config, cross)


# ======================================================================================
# The allowlist is gone
# ======================================================================================


def test_the_rule_id_allowlist_constants_no_longer_exist() -> None:
    """The defect, stated as an assertion.

    Not "the new link works" -- a codebase can have both, and then the allowlist is
    still deciding which cross-domain cases exist. The names are gone from the module.
    """
    assert not hasattr(correlator_module, "_AUTH_RULES")
    assert not hasattr(correlator_module, "_REMOTE_EXEC_RULES")


def test_no_detection_rule_id_is_a_literal_the_correlator_reads() -> None:
    """A weaker allowlist would be a new list of rule ids somewhere else in the file.

    Rule ids in prose are history and explanation -- the module docstring quotes the
    allowlist it replaced, which is the point. What must not exist is a rule id the
    *code* compares against, so this walks the AST and looks at every string constant
    that is not a docstring.
    """
    import ast

    source = Path(correlator_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                docstrings.add(id(body[0].value))
        # An attribute docstring: a bare string expression after an assignment.
        if isinstance(node, ast.Module) or isinstance(node, ast.ClassDef):
            for statement in getattr(node, "body", []):
                if (isinstance(statement, ast.Expr)
                        and isinstance(statement.value, ast.Constant)
                        and isinstance(statement.value.value, str)):
                    docstrings.add(id(statement.value))

    offenders = [
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
        and re.fullmatch(r"(ATH|AWS|K8S)-\d+", node.value)
    ]
    assert offenders == [], "rule id(s) read by correlator code: {}".format(offenders)


def test_every_channel_is_classified_or_deliberately_unclassified() -> None:
    """The stale-table failure mode, closed.

    An allowlist rots because nothing tells you a new rule was not added to it. This
    table is total over the channel vocabulary, and a channel added without a family is
    a failing test rather than a link that silently stops firing.
    """
    classified = set(CHANNEL_FAMILY) | set(CHANNELS_WITHOUT_FAMILY)
    assert classified == set(TelemetryChannel)
    assert not (set(CHANNEL_FAMILY) & set(CHANNELS_WITHOUT_FAMILY))
    assert set(CHANNEL_FAMILY.values()) == {
        "endpoint", "identity", "network", "control_plane",
    }


# ======================================================================================
# identity x control_plane: the pair the audit measured as unreachable
# ======================================================================================


def test_identity_and_control_plane_link_on_a_shared_principal() -> None:
    telemetry, auth, control = _cloud_pair(gap_minutes=5)
    score, signals, structural = _signals(auth, control, telemetry)
    assert structural
    assert any(s.startswith("shared_principal") for s in signals)
    assert "dev_alice" in [s for s in signals if s.startswith("shared_principal")][0]
    assert score >= CorrelationConfig().min_score
    assert len(correlate([auth, control], telemetry)) == 1


def test_identity_and_control_plane_do_not_link_outside_the_window() -> None:
    """One minute past ``cross_domain_window`` and the same two findings stay apart."""
    minutes = int(CROSS_DOMAIN_WINDOW.total_seconds() // 60) + 1
    telemetry, auth, control = _cloud_pair(gap_minutes=minutes)
    _, signals, structural = _signals(auth, control, telemetry)
    assert not any(s.startswith("shared_principal") for s in signals)
    assert not structural
    assert len(correlate([auth, control], telemetry)) == 2


def test_identity_and_control_plane_do_not_link_on_different_principals() -> None:
    """Same window, same AWS account, a different principal: no link.

    The pair keeps every circumstantial signal the linking pair had except the account
    -- same account-level device, five minutes apart -- so the principal is the only
    thing that differs, and it is the whole difference.
    """
    telemetry, auth, control = _cloud_pair(gap_minutes=5, control_actor="svc_build")
    _, signals, structural = _signals(auth, control, telemetry)
    assert not any(s.startswith("shared_principal") for s in signals)
    assert not structural
    assert any(s.startswith("same_device") for s in signals)
    assert any(s.startswith("temporal_close") for s in signals)
    assert len(correlate([auth, control], telemetry)) == 2


def test_a_grant_links_to_the_grantee_not_only_to_the_caller() -> None:
    """``target_actor`` counts. A grant names the principal whose authority it changed,
    and that principal's own later activity is what makes the chain a chain."""
    telemetry = _telemetry(
        controls=[
            _row(
                "control", "evt-grant", 0, user="ci-deployer", actor="ci-deployer",
                target_actor="dev_alice", verb="create",
                resource_type="iam:policy", decision="allowed",
            )
        ],
        logons=[_row("logon", "evt-auth", 3, user="dev_alice", action="success")],
    )
    grant = _finding(
        "AWS-001", event_id="evt-grant", minute=0,
        device="aws:111122223333/us-east-1", user="ci-deployer", channels=CONTROL,
    )
    auth = _finding(
        "ATH-005", event_id="evt-auth", minute=3,
        device="aws:111122223333/us-east-1", user="dev_alice", channels=IDENTITY,
    )
    _, signals, structural = _signals(grant, auth, telemetry)
    assert structural
    assert any("dev_alice" in s for s in signals if s.startswith("shared_principal"))


# ======================================================================================
# endpoint x network: the other pair the allowlist could never reach
# ======================================================================================


def test_endpoint_and_network_link_on_the_same_user_and_device() -> None:
    telemetry = _telemetry(
        process=[
            _row("process", "evt-proc", 0, device="PC01", user="jdoe",
                 process_name="powershell.exe", process_id=6612,
                 parent_process_id=600)
        ],
        network=[
            _row("network", "evt-net", 4, device="PC01", user="jdoe",
                 process_name="powershell.exe", process_id=7777,
                 remote_ip="185.220.101.47", direction="outbound")
        ],
    )
    endpoint = _finding(
        "ATH-002", event_id="evt-proc", minute=0, device="PC01", user="jdoe",
        channels=ENDPOINT,
    )
    network = _finding(
        "ATH-003N", event_id="evt-net", minute=4, device="PC01", user="jdoe",
        channels=NETWORK,
    )
    _, signals, structural = _signals(endpoint, network, telemetry)
    assert structural
    assert any(s.startswith("shared_principal") for s in signals)
    assert len(correlate([endpoint, network], telemetry)) == 1


def test_two_findings_of_the_same_family_are_not_linked_by_this_predicate() -> None:
    """Two endpoint findings on one host and one account: the naive-correlation case.

    They share a principal, a device and a minute, and they must still be refused --
    that is what the existing structural signals are for, and a cross-*channel* link
    that fired within one channel would be time-and-user correlation wearing a new name.
    """
    telemetry = _telemetry(
        process=[
            _row("process", "evt-a", 0, device="PC01", user="jdoe",
                 process_name="powershell.exe", process_id=10,
                 parent_process_id=600),
            _row("process", "evt-b", 2, device="PC01", user="jdoe",
                 process_name="cmd.exe", process_id=11,
                 parent_process_id=601),
        ],
    )
    a = _finding("ATH-002", event_id="evt-a", minute=0, device="PC01", user="jdoe",
                 channels=ENDPOINT)
    b = _finding("ATH-008", event_id="evt-b", minute=2, device="PC01", user="jdoe",
                 channels=ENDPOINT)
    score, signals, structural = _signals(a, b, telemetry)
    assert not any(s.startswith("shared_principal") for s in signals)
    assert not structural
    assert score >= CorrelationConfig().min_score
    assert len(correlate([a, b], telemetry)) == 2


def test_a_finding_spanning_two_families_does_not_link_to_either_of_them() -> None:
    """ATH-003 declares network flow *and* process execution, so an endpoint finding is
    not a second domain for it -- one stage described twice is not two stages. This is
    the same judgement ``ath.evaluation.necessity`` makes when it calls such a case
    redundant, enforced here so the correlator cannot manufacture the case the audit
    would then reject."""
    telemetry = _telemetry(
        process=[
            _row("process", "evt-proc", 0, device="PC01", user="jdoe",
                 process_name="powershell.exe", process_id=10,
                 parent_process_id=600)
        ],
        network=[
            _row("network", "evt-net", 3, device="PC01", user="jdoe",
                 process_name="powershell.exe", process_id=11,
                 remote_ip="8.8.8.8", direction="outbound")
        ],
    )
    both = _finding(
        "ATH-003", event_id="evt-net", minute=3, device="PC01", user="jdoe",
        channels=frozenset(
            {TelemetryChannel.NETWORK_FLOW, TelemetryChannel.PROCESS_EXECUTION}
        ),
    )
    endpoint = _finding(
        "ATH-002", event_id="evt-proc", minute=0, device="PC01", user="jdoe",
        channels=ENDPOINT,
    )
    _, signals, _structural = _signals(both, endpoint, telemetry)
    assert not any(s.startswith("shared_principal") for s in signals)
    assert channel_families(both) == frozenset({"network", "endpoint"})


def test_a_finding_with_no_classifiable_channel_forms_no_cross_channel_link() -> None:
    telemetry = _telemetry(
        logons=[_row("logon", "evt-auth", 0, user="dev_alice", action="success")],
        controls=[_row("control", "evt-ctl", 2, user="dev_alice", actor="dev_alice",
                       verb="create", resource_type="iam:accesskey")],
    )
    nameless = Finding(
        rule_id="XXX-999", title="t", severity=Severity.HIGH,
        device="aws:111122223333/us-east-1", user="dev_alice",
        evidence=(Evidence("evt-ctl", START + timedelta(minutes=2), "s"),),
        reason="r",
    )
    auth = _finding(
        "ATH-005", event_id="evt-auth", minute=0,
        device="aws:111122223333/us-east-1", user="dev_alice", channels=IDENTITY,
    )
    assert channel_families(nameless) == frozenset()
    _, signals, structural = _signals(auth, nameless, telemetry)
    assert not any(s.startswith("shared_principal") for s in signals)
    assert not structural


# ======================================================================================
# auth_then_exec kept its meaning
# ======================================================================================


def test_auth_then_exec_still_fires_without_a_shared_principal() -> None:
    """The reason it is not folded into ``shared_principal``: a service-launched shell
    runs as the service account, not as the account that authenticated."""
    telemetry = _telemetry(
        logons=[_row("logon", "evt-auth", 0, device="FS02", user="svc_backup",
                     action="success", logon_type=3)],
        process=[_row("process", "evt-exec", 1, device="FS02", user="SYSTEM",
                      process_name="cmd.exe", process_id=99,
                      parent_process_id=4)],
    )
    auth = _finding("ATH-006", event_id="evt-auth", minute=0, device="FS02",
                    user="svc_backup", channels=IDENTITY)
    execution = _finding("ATH-007", event_id="evt-exec", minute=1, device="FS02",
                         user="SYSTEM", channels=ENDPOINT)
    cross = _CrossChannelIndex(telemetry, [auth, execution])
    assert not (cross.principals(auth) & cross.principals(execution))
    _, signals, structural = _signals(auth, execution, telemetry)
    assert structural
    assert any(s.startswith("auth_then_exec") for s in signals)


def test_auth_then_exec_is_not_claimed_across_hosts() -> None:
    telemetry = _telemetry(
        logons=[_row("logon", "evt-auth", 0, device="FS02", user="svc_backup",
                     action="success")],
        process=[_row("process", "evt-exec", 1, device="PC09", user="SYSTEM",
                      process_name="cmd.exe", process_id=99,
                      parent_process_id=4)],
    )
    auth = _finding("ATH-006", event_id="evt-auth", minute=0, device="FS02",
                    user="svc_backup", channels=IDENTITY)
    execution = _finding("ATH-007", event_id="evt-exec", minute=1, device="PC09",
                         user="SYSTEM", channels=ENDPOINT)
    _, signals, _ = _signals(auth, execution, telemetry)
    assert not any(s.startswith("auth_then_exec") for s in signals)


# ======================================================================================
# Configuration
# ======================================================================================


def test_the_window_default_is_the_declared_constant() -> None:
    """The pre-registration quotes the constant, so the constant is what the config
    uses -- not a literal that could drift away from it."""
    assert CorrelationConfig().cross_domain_window == CROSS_DOMAIN_WINDOW
    assert CROSS_DOMAIN_WINDOW == CorrelationConfig().auth_exec_window


def test_a_cross_domain_window_wider_than_max_gap_is_refused() -> None:
    """A setting that is silently ignored is worse than one that is refused."""
    with pytest.raises(ValueError, match="cross_domain_window"):
        CorrelationConfig(cross_domain_window=timedelta(hours=2))


def test_principal_columns_cover_every_canonical_table() -> None:
    assert set(PRINCIPAL_COLUMNS) == {"process", "network", "logon", "control"}
    assert PRINCIPAL_COLUMNS["control"] == ("actor", "target_actor")


def test_a_shared_principal_alone_does_not_reach_the_score_bar() -> None:
    """+3 against ``min_score`` 5: the principal needs a circumstantial signal to agree
    with it, which is the same arithmetic that stops three circumstantial signals from
    linking on their own."""
    from ath.correlation.correlator import W_SHARED_PRINCIPAL

    assert W_SHARED_PRINCIPAL < CorrelationConfig().min_score


# ======================================================================================
# The benchmark case that must not move
# ======================================================================================


@pytest.fixture(scope="module")
def inc_001():
    root = Path(__file__).resolve().parent.parent
    suite = standard_suite(
        root / "data" / "raw",
        root / "tests" / "fixtures" / "cloudtrail",
        root / "tests" / "fixtures" / "k8s_audit",
    )
    return [i for i in suite if i.incident_id == "INC-001"][0]


def test_inc_001_case_is_unchanged(inc_001) -> None:
    """The one qualifying cross-domain case in the repository, pinned to M19's record.

    ``reports/m19/ablation/MANIFEST.json`` recorded 13 findings, one case, 11 findings in
    it and 31 evidence ids; ``arm_A.json`` recorded event recall 1.0 at 100% purity. A
    correlation change that moved any of those would have changed the baseline M19's
    primary result rests on, which is the one thing this task may not do.
    """
    outcome = run_incident(inc_001)
    assert outcome.findings == 13
    assert outcome.cases == 1
    assert outcome.noise_cases == 0
    assert outcome.primary_case_recall == 1.0
    assert outcome.primary_case_purity == 1.0
    assert outcome.event_recall == 1.0
    assert outcome.passed


def test_inc_001_case_has_the_same_finding_set(inc_001) -> None:
    from ath.environment import build_environment_model
    from ath.hunting import HuntConfig, run_hunt
    from ath.triage import assess_findings, set_aside_ids

    telemetry = inc_001.telemetry
    hunt = run_hunt(telemetry, config=HuntConfig())
    assessments = assess_findings(hunt.findings, build_environment_model(telemetry))
    cases = correlate(
        hunt.findings, telemetry, set_aside=set_aside_ids(assessments),
    )
    assert len(cases) == 1
    case = cases[0]
    assert len(case.findings) == 11
    assert len(case.event_ids) == 31
    assert sorted(case.rule_ids) == [
        "ATH-001", "ATH-002", "ATH-003", "ATH-004", "ATH-005",
        "ATH-006", "ATH-007", "ATH-008", "ATH-009", "ATH-010",
    ]
