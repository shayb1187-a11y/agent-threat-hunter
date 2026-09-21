"""What the agent is told about a process, and what it is told it cannot know.

The invariant under test
------------------------
**When both sides of a process join carry an instance identity of the same scheme, the
join is by identity and nothing else. When either side lacks one, or the schemes differ,
the join falls back to ``(device, pid)`` and the result is labelled "inferred from
pid".**

Here that lands on three surfaces: the ``process_tree`` tool, the metadata a rule hands
forward, and the sentences the endpoint specialist writes. The failure it removes is
specific and was live: ``process_tree`` resolved a PID with ``match.iloc[0]`` -- the
first row in file order -- and then walked *that* row's ancestors. On the COMISET slice,
``desktop-4pvps6e`` PID 5924 was held by 27 different processes, so the tool returned a
three-generation chain assembled from three unrelated instances, and the specialist
turned it into a FACT: "X (PID 5924) was started by Y". Nothing in the output said that
26 other answers were equally available.

Tests marked FAILS ON HEAD fail against the pre-M18b-2 tool, which picked one.
"""

from __future__ import annotations

import pytest

from _builders import at, net, proc
from _builders import telemetry as build_telemetry
from ath.agent.claims import ClaimType, ClaimVerifier
from ath.agent.specialists import EndpointAgent
from ath.agent.state import InvestigationState
from ath.agent.tools import ToolBox
from ath.correlation.chain import InvestigationCase
from ath.hunting import Evidence, Finding, HuntConfig, Severity, run_hunt
from ath.instance_identity import INFERRED_FROM_PID, RESOLVED_BY_IDENTITY, start_identity
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.loader import load_telemetry

DEVICE = "PC09"
REUSED_PID = 4444


# ======================================================================================
# Fixtures: one host, three shapes of the same lineage
# ======================================================================================


def _chain_rows(*, identified: bool) -> list[dict]:
    """explorer -> cmd(4444) -> powershell(5555) -> whoami(6666), with or without ids."""
    cmd_id = start_identity(DEVICE, REUSED_PID, at(0)) if identified else ""
    ps_id = start_identity(DEVICE, 5555, at(1)) if identified else ""
    return [
        proc("cmd.exe", "cmd.exe /c one", "explorer.exe", device=DEVICE, user="operator",
             when=at(0), pid=REUSED_PID, ppid=1000, guid=cmd_id),
        proc("powershell.exe", "powershell -enc AAA", "cmd.exe", device=DEVICE,
             user="operator", when=at(1), pid=5555, ppid=REUSED_PID, guid=ps_id,
             parent_guid=cmd_id),
        proc("whoami.exe", "whoami /all", "powershell.exe", device=DEVICE,
             user="operator", when=at(2), pid=6666, ppid=5555,
             guid=start_identity(DEVICE, 6666, at(2)) if identified else "",
             parent_guid=ps_id),
    ]


@pytest.fixture()
def identified():
    """Every row names its instance and its creator."""
    return build_telemetry(procs=_chain_rows(identified=True))


@pytest.fixture()
def silent():
    """The same lineage from a source that records no identity at all."""
    return build_telemetry(procs=_chain_rows(identified=False))


@pytest.fixture()
def ambiguous():
    """The identified chain, plus a *second* run of PID 4444 an hour later."""
    rows = _chain_rows(identified=True)
    rows.append(
        proc("rundll32.exe", "rundll32 evil.dll,Start", "explorer.exe", device=DEVICE,
             user="operator", when=at(60), pid=REUSED_PID, ppid=1000,
             guid=start_identity(DEVICE, REUSED_PID, at(60)))
    )
    return build_telemetry(procs=rows)


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    """The generated corpus, through the loader the CLI uses.

    Its five reused ``(device, pid)`` keys are the reason the registry test below is not
    hypothetical.
    """
    tables, ground_truth = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("identity_corpus")
    write_telemetry(tables, ground_truth, out)
    return load_telemetry(out)


def toolbox(data) -> ToolBox:
    return ToolBox(data, [], [])


# ======================================================================================
# process_tree
# ======================================================================================


def test_an_identity_walks_the_exact_chain(identified) -> None:
    tools = toolbox(identified)
    ps_identity = start_identity(DEVICE, 5555, at(1))

    tree = tools.process_tree(DEVICE, process_guid=ps_identity, agent="t")

    assert tree["resolution"] == RESOLVED_BY_IDENTITY
    assert [a["process_name"] for a in tree["ancestry"]] == ["powershell.exe", "cmd.exe"]
    assert {a["resolved_by"] for a in tree["ancestry"]} == {RESOLVED_BY_IDENTITY}
    assert tree["pid"] == 5555


def test_a_pid_only_one_instance_held_resolves_to_that_instance(identified) -> None:
    tools = toolbox(identified)

    tree = tools.process_tree(DEVICE, 5555, agent="t")

    assert tree["resolution"] == "pid_unique"
    assert tree["process_guid"] == start_identity(DEVICE, 5555, at(1))
    assert [a["process_name"] for a in tree["ancestry"]] == ["powershell.exe", "cmd.exe"]


def test_an_ambiguous_pid_returns_candidates_and_never_a_chain(ambiguous) -> None:
    """FAILS ON HEAD: ``iloc[0]`` returned one instance's ancestry as the answer.

    Two processes held PID 4444. The honest answer is both of them, with what tells them
    apart, and no lineage -- not the earlier one's ancestry presented as though the
    question had been settled.
    """
    tools = toolbox(ambiguous)

    tree = tools.process_tree(DEVICE, REUSED_PID, agent="t")

    assert tree["resolution"] == "ambiguous_pid"
    assert tree["ambiguous_pid"] == 2
    assert tree["ancestry"] == [] and tree["children"] == []
    assert {c["process_name"] for c in tree["candidates"]} == {"cmd.exe", "rundll32.exe"}
    assert all(c["process_guid"] and c["timestamp"] for c in tree["candidates"]), (
        "a candidate a caller cannot tell apart from the others is not a candidate"
    )


def test_the_ambiguity_is_resolvable_by_asking_with_an_identity(ambiguous) -> None:
    """The candidates are not a dead end: they carry what the next call needs."""
    tools = toolbox(ambiguous)
    candidates = tools.process_tree(DEVICE, REUSED_PID, agent="t")["candidates"]
    chosen = next(c for c in candidates if c["process_name"] == "rundll32.exe")

    tree = tools.process_tree(DEVICE, process_guid=chosen["process_guid"], agent="t")

    assert tree["resolution"] == RESOLVED_BY_IDENTITY
    assert [a["process_name"] for a in tree["ancestry"]] == ["rundll32.exe"]


def test_rows_without_identities_are_walked_and_every_hop_says_so(silent) -> None:
    """The fallback is a working walk, not a refusal -- and it is labelled throughout."""
    tools = toolbox(silent)

    tree = tools.process_tree(DEVICE, 6666, agent="t")

    assert [a["process_name"] for a in tree["ancestry"]] == [
        "whoami.exe", "powershell.exe", "cmd.exe",
    ]
    assert [a["resolved_by"] for a in tree["ancestry"]] == [INFERRED_FROM_PID] * 3
    assert {a["parent_resolution"] for a in tree["ancestry"]} == {INFERRED_FROM_PID}


def test_a_parent_that_is_named_but_not_observed_stops_the_walk_honestly() -> None:
    """The parent started before the capture: a gap, reported, not filled by a pid.

    FAILS ON HEAD: the old walk matched the parent's *number* and would have attached
    whatever process held it -- which, on a reused slot, is a different program.
    """
    absent_parent = start_identity(DEVICE, 1000, at(-600))
    impostor = proc("chrome.exe", "chrome", "explorer.exe", device=DEVICE,
                    user="operator", when=at(-1), pid=1000, ppid=1,
                    guid=start_identity(DEVICE, 1000, at(-1)))
    child = proc("cmd.exe", "cmd.exe", "explorer.exe", device=DEVICE, user="operator",
                 when=at(0), pid=REUSED_PID, ppid=1000,
                 guid=start_identity(DEVICE, REUSED_PID, at(0)),
                 parent_guid=absent_parent)
    tools = toolbox(build_telemetry(procs=[impostor, child]))

    tree = tools.process_tree(DEVICE, REUSED_PID, agent="t")

    assert [a["process_name"] for a in tree["ancestry"]] == ["cmd.exe"]
    assert any("created before the capture began" in n for n in tree["notes"])


def test_children_are_attributed_to_the_instance_that_started_them(ambiguous) -> None:
    """powershell belongs to the first run of PID 4444, and to no other."""
    tools = toolbox(ambiguous)
    first = start_identity(DEVICE, REUSED_PID, at(0))
    second = start_identity(DEVICE, REUSED_PID, at(60))

    assert [c["process_name"] for c in
            tools.process_tree(DEVICE, process_guid=first, agent="t")["children"]] == [
        "powershell.exe"
    ]
    assert tools.process_tree(DEVICE, process_guid=second, agent="t")["children"] == []


def test_a_child_that_names_no_parent_instance_is_still_found_and_labelled() -> None:
    """Half-identified telemetry: the parent names itself, the child does not."""
    parent_identity = start_identity(DEVICE, REUSED_PID, at(0))
    parent = proc("cmd.exe", "cmd.exe", "explorer.exe", device=DEVICE, user="operator",
                  when=at(0), pid=REUSED_PID, ppid=1000, guid=parent_identity)
    child = proc("whoami.exe", "whoami", "cmd.exe", device=DEVICE, user="operator",
                 when=at(1), pid=6666, ppid=REUSED_PID,
                 guid=start_identity(DEVICE, 6666, at(1)), parent_guid="")
    tools = toolbox(build_telemetry(procs=[parent, child]))

    children = tools.process_tree(DEVICE, process_guid=parent_identity, agent="t")["children"]

    assert [c["process_name"] for c in children] == ["whoami.exe"]
    assert children[0]["resolved_by"] == INFERRED_FROM_PID


def test_search_and_network_results_carry_the_instance_identity() -> None:
    """Every row a tool hands the agent says which run it is about, or admits it cannot."""
    identity = start_identity(DEVICE, REUSED_PID, at(0))
    rows = [proc("cmd.exe", "cmd.exe", "explorer.exe", device=DEVICE, when=at(0),
                 pid=REUSED_PID, ppid=1000, guid=identity)]
    connections = [
        net("cmd.exe", "185.220.101.47", device=DEVICE, when=at(n), pid=REUSED_PID,
            guid=identity)
        for n in range(3)
    ]
    tools = toolbox(build_telemetry(procs=rows, nets=connections))

    assert tools.search_processes(device=DEVICE, agent="t")["results"][0][
        "process_guid"
    ] == identity

    destinations = tools.host_network_activity(DEVICE, agent="t")["destinations"]
    assert destinations[0]["process_guid"] == identity
    assert destinations[0]["process_instances"] == 1


def test_a_destination_contacted_by_two_instances_names_neither() -> None:
    """"chrome.exe contacted X 400 times" is a different fact for one browser than forty."""
    connections = [
        net("chrome.exe", "203.0.113.9", device=DEVICE, when=at(0), pid=REUSED_PID,
            guid=start_identity(DEVICE, REUSED_PID, at(0))),
        net("chrome.exe", "203.0.113.9", device=DEVICE, when=at(60), pid=REUSED_PID,
            guid=start_identity(DEVICE, REUSED_PID, at(60))),
    ]
    tools = toolbox(build_telemetry(nets=connections))

    destination = tools.host_network_activity(DEVICE, agent="t")["destinations"][0]

    assert destination["process_instances"] == 2
    assert destination["process_guid"] == ""


# ======================================================================================
# The endpoint specialist's sentences
# ======================================================================================


def _case(data, *, event_id: str, metadata: dict) -> tuple[InvestigationState, ToolBox]:
    finding = Finding(
        rule_id="ATH-002", title="t", severity=Severity.HIGH, device=DEVICE,
        user="operator", evidence=(Evidence(event_id, at(1), "s"),), reason="r",
        metadata=metadata,
        fields_used=("process_name", "process_id", "parent_process_name"),
    )
    case = InvestigationCase(case_id="CASE-001", findings=(finding,))
    return InvestigationState(case=case), ToolBox(data, [finding], [case])


def test_the_specialist_names_the_ambiguity_and_asserts_no_parentage(ambiguous) -> None:
    """FAILS ON HEAD: it asserted a FACT about whichever instance came first in the file.

    An INFERENCE that the attribution cannot be made is a useful thing to tell an
    analyst. A FACT about one of two candidate processes is not a weaker version of it;
    it is a different, wrong statement.
    """
    rows = ambiguous.processes
    first_run = rows[rows["process_id"] == REUSED_PID].iloc[0]
    state, tools = _case(
        ambiguous, event_id=first_run["event_id"],
        metadata={"process_id": REUSED_PID},
    )

    result = EndpointAgent(tools).investigate(state)

    inferences = [c for c in result.claims if c.claim_type is ClaimType.INFERENCE]
    assert any("2 different process instances" in c.statement for c in inferences), (
        [c.statement for c in result.claims]
    )
    assert not any(
        c.claim_type is ClaimType.FACT and "was started by" in c.statement
        for c in result.claims
    ), "no parentage may be asserted for a pid two processes held"


def test_the_specialist_prefers_the_identity_the_finding_carries(ambiguous) -> None:
    """The same ambiguous corpus, a finding that names its instance: a clean answer."""
    state, tools = _case(
        ambiguous, event_id="ignored",
        metadata={"process_id": REUSED_PID,
                  "process_guid": start_identity(DEVICE, REUSED_PID, at(60))},
    )

    result = EndpointAgent(tools).investigate(state)
    facts = [c.statement for c in result.claims if c.claim_type is ClaimType.FACT]

    # The *second* run, which is the one the finding named -- not the first, which is
    # what a pid look-up would have reached for.
    assert any("rundll32.exe (PID 4444) was started by explorer.exe" in f for f in facts), facts
    assert not any("cmd.exe (PID 4444)" in f for f in facts)
    # explorer.exe is named by this row and identified by nothing, so the claim about
    # *it* still carries the label. The label travels with the join it describes.
    assert all(
        f"explorer.exe (PID 1000, identity {INFERRED_FROM_PID})" in f
        for f in facts if "was started by" in f
    ), facts


def test_an_identified_lineage_carries_no_inferred_label(identified) -> None:
    ps = identified.processes
    event_id = ps[ps["process_id"] == 5555].iloc[0]["event_id"]
    state, tools = _case(identified, event_id=event_id, metadata={"process_id": 5555})

    result = EndpointAgent(tools).investigate(state)
    facts = [c.statement for c in result.claims if c.claim_type is ClaimType.FACT]

    assert any("powershell.exe (PID 5555) was started by cmd.exe" in f for f in facts), facts
    assert not any(INFERRED_FROM_PID in f for f in facts), facts


def test_a_lineage_with_no_identities_says_it_was_inferred_from_the_pid(silent) -> None:
    ps = silent.processes
    event_id = ps[ps["process_id"] == 5555].iloc[0]["event_id"]
    state, tools = _case(silent, event_id=event_id, metadata={"process_id": 5555})

    result = EndpointAgent(tools).investigate(state)
    facts = [c.statement for c in result.claims if c.claim_type is ClaimType.FACT]

    started_by = next(f for f in facts if "was started by" in f)
    assert f"identity {INFERRED_FROM_PID}" in started_by, started_by
    chain = next(f for f in facts if "Execution chain" in f)
    assert INFERRED_FROM_PID in chain, chain


def test_every_claim_the_specialist_makes_still_verifies(ambiguous, silent) -> None:
    """The labels are added to statements, never to the evidence: citations still exist."""
    for data, metadata in (
        (ambiguous, {"process_id": REUSED_PID}),
        (silent, {"process_id": 5555}),
    ):
        rows = data.processes
        event_id = rows.iloc[0]["event_id"]
        state, tools = _case(data, event_id=event_id, metadata=metadata)
        result = EndpointAgent(tools).investigate(state)

        verified = ClaimVerifier(data).verify(list(result.claims))
        assert verified.rejected == [], verified.to_dict()
        assert verified.accepted, "the specialist must still have said something"


# ======================================================================================
# What a rule hands forward
# ======================================================================================


def test_a_finding_that_names_a_pid_also_names_the_instance(generated) -> None:
    """Over every registered rule, on the generated corpus.

    A rule that puts ``process_id`` in metadata is telling a consumer "this is the
    process" -- and on that corpus five ``(device, pid)`` keys are held by two processes
    each, so the pid alone cannot be that. Written over the registry rather than over
    ATH-003 so a rule added later is covered by it without being listed here.
    """
    findings = run_hunt(generated, config=HuntConfig()).findings
    telemetry = generated
    rows = {}
    for frame in (telemetry.processes, telemetry.network):
        if "process_guid" not in frame.columns:
            continue
        for row in frame[["event_id", "process_guid"]].to_dict("records"):
            rows[row["event_id"]] = str(row["process_guid"] or "")

    checked = 0
    for finding in findings:
        if finding.metadata.get("process_id") is None:
            continue
        checked += 1
        assert "process_guid" in finding.metadata, (
            f"{finding.rule_id} names a pid and not the instance holding it"
        )
        observed = {rows.get(e, "") for e in finding.event_ids} - {""}
        expected = next(iter(observed)) if len(observed) == 1 else ""
        assert finding.metadata["process_guid"] == expected, (
            f"{finding.rule_id} metadata identity disagrees with its own evidence"
        )

    assert checked, "no finding carried a process_id, so this test proved nothing"
