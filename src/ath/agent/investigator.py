"""The D1 bounded investigator: one local model, one evidence-seeking loop.

Why this module exists
----------------------
The first D1 preview (``reports/local/dev/D1_AUDIT.md``) showed that arm B's
architecture -- seven facets of one generalist walked to exhaustion, then one synthesis
pass over the detector's sentences -- cannot investigate: the set of tool calls is fixed
by ``plan_walk`` before the model is asked anything, the process lineage is never walked
because the ATH-007 finding does not carry a pid, and synthesis can only paraphrase what
it was handed. D1 therefore gets its own loop, here, and hosted arms B and C keep theirs.

The loop
--------
::

    seed      get_finding for every member finding, get_events over the case's cited ids
              (raw rows: logon types, sources, command lines), lookup_technique for the
              mapped techniques. Deterministic; every result is a tool-authored FACT.
    round r   the model sees the observations so far and a MENU of probes built from the
              case's own evidence, and answers with JSON:
                <= 3 competing explanations (malicious / benign / insufficient), each
                   citing <= 6 event ids it was shown;
                the single most decision-relevant evidence gap;
                at most ONE probe from the menu, or "none";
                a disposition: malicious, benign or abstain.
    probe     the chosen probe runs (one recorded tool call); its result becomes a
              tool-authored FACT and a new observation; back to the next round.
    stop      when the model answers "none", when the probe budget is spent, or when a
              model call fails. The final round's explanations become the model's claims
              (INFERENCE when they cite shown evidence, HYPOTHESIS when they cite none)
              and go through ClaimVerifier like every other claim.

What is bounded, and where
---------------------------
* :data:`MAX_PROBES` probe rounds, so at most ``MAX_PROBES + 1`` model calls per case.
* :data:`MAX_EXPLANATIONS` explanations and :data:`MAX_EVIDENCE_PER_EXPLANATION` ids per
  explanation, enforced twice: in the JSON schema the local client sends as ``format``
  (grammar-constrained decoding) and again on parse, so a client without schema support
  is bounded the same way.
* :data:`INVESTIGATOR_MAX_TOKENS` output tokens per call. A truncated reply is an error
  (the client already says so) and degrades the row; it is never retried.
* The step budget and the tool-call cap of the arm still apply: every probe is one
  orchestrator-style step and every tool call goes through the same ``ToolBox``.

What the model can and cannot do
--------------------------------
It chooses from a menu whose entries -- tool, arguments, what the tool retrieves, when
to use it and when not -- were built deterministically from evidence already in the
state. It cannot invent an argument, call a tool twice, author a FACT, or cite an id it
was not shown. Labels never reach it: this module reads the case and the toolbox, and
nothing else.

Diagnostics
-----------
Every round is recorded on ``state.investigation`` in compact machine-readable fields
(explanation labels, the stated gap, the chosen probe and its one-line reason, how many
new ids the probe returned and how many the final claims used, whether the labels or
the disposition changed after the probe, whether the output was truncated). No
chain-of-thought is requested or stored.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Sequence

from ath.agent.claims import Claim, ClaimType, ClaimVerifier
from ath.agent.contract import check_prompt_contract
from ath.agent.llm import LLMClient, LLMResponse, NullLLM
from ath.agent.state import AgentResult, InvestigationState, InvestigationStatus
from ath.agent.tools import ToolBox
from ath.correlation.chain import InvestigationCase
from ath.logging_setup import get_logger

logger = get_logger(__name__)

# --------------------------------------------------------------------------------------
# The bounds
# --------------------------------------------------------------------------------------

D1_PROMPT_VERSION = "d1-investigator-v3"
"""Named version of the prompts, schema and bounds below. Written into every row header
and into the local freeze; a change here is a change of experiment."""

FAMILY = "investigator"
"""The agent family every step of this loop reports under (``investigator:seed``,
``investigator:probe``, ``investigator:conclude``). One family, so completeness counts
one agent, as it does for arm B's facets."""

MAX_PROBES = 2
"""Rounds in which the model may choose one probe. At most ``MAX_PROBES + 1`` model calls."""

MAX_EXPLANATIONS = 3
MAX_EVIDENCE_PER_EXPLANATION = 6
MAX_MENU = 8
"""Probes offered per round. Deterministic order; see :func:`build_menu`."""

BUILTIN_ACCOUNTS: frozenset[str] = frozenset({
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "NT AUTHORITY\\SYSTEM", "ROOT", "-",
})
"""Accounts whose authentication history is a machine's, not a person's; an account
probe on them answers no question about who used a credential."""

MAX_IDS_SHOWN = 8
"""Event ids rendered per observation. The count of the rest is always shown."""

MAX_ROWS_SHOWN = 8
"""Rows rendered per tool result (children, logon events, raw rows)."""

INVESTIGATOR_MAX_TOKENS = 768
"""Output budget per call. Three short explanations, a gap, a probe id and a reason fit
in well under 400 tokens; the old 2048 let the model copy id lists until the cap."""

STATEMENT_CHARS = 300
"""Longest statement kept from the model, and longest recorded in diagnostics."""

RAW_REPLY_CHARS = 2000
"""Longest raw model reply recorded per round in the row's diagnostics. Not a bound the
model reads and not in :func:`prompt_hashes`: it changes what a row records, never what
the model sees, so rows before and after its introduction summarise together."""

LABELS: tuple[str, ...] = ("malicious", "benign", "insufficient")
DISPOSITIONS: tuple[str, ...] = ("malicious", "benign", "abstain")
NO_PROBE = "none"

RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "explanations": {
            "type": "array",
            "maxItems": MAX_EXPLANATIONS,
            "items": {
                "type": "object",
                "properties": {
                    "label": {"type": "string", "enum": list(LABELS)},
                    "statement": {"type": "string"},
                    "evidence": {
                        "type": "array",
                        "maxItems": MAX_EVIDENCE_PER_EXPLANATION,
                        "items": {"type": "string"},
                    },
                },
                "required": ["label", "statement", "evidence"],
            },
        },
        "evidence_gap": {"type": "string"},
        "next_probe": {"type": "string"},
        "probe_reason": {"type": "string"},
        "disposition": {"type": "string", "enum": list(DISPOSITIONS)},
    },
    "required": ["explanations", "evidence_gap", "next_probe", "probe_reason", "disposition"],
}
"""The JSON schema the local client sends as ``format``. The same bounds are re-applied
on parse, so the schema is a cost control, not the safeguard."""


# --------------------------------------------------------------------------------------
# The prompts (hashed into the local freeze; see ``ath.evaluation.ablation.local``)
# --------------------------------------------------------------------------------------

INVESTIGATOR_SYSTEM = (
    "You are a single security investigator working one alert case. You reason from "
    "the observations you are shown and from nothing else.\n"
    "\n"
    "Detector findings are OBSERVATIONS, not conclusions. A detection rule fires on a "
    "pattern that has both malicious and benign causes, and the rule does not know which "
    "one it saw. Treat the rule's own sentence as one reading of the pattern, never as "
    "the verdict.\n"
    "\n"
    "Each turn:\n"
    "1. Give at most 3 competing explanations that account for ALL the observations "
    "together. Label each \"malicious\", \"benign\" or \"insufficient\". Include a benign "
    "explanation whenever the observations are consistent with one, and say which "
    "observed detail makes it plausible here. Never force a malicious explanation. Use "
    "\"insufficient\" only when no observation favours either side; it is not a default "
    "third entry.\n"
    "2. For each explanation list the event ids it rests on (at most 6, only ids you were "
    "shown). Prefer the ids of the rows that decide it: a child process, a specific "
    "logon, a specific command. An explanation with no ids is an unsupported hypothesis.\n"
    "3. Name the single most decision-relevant evidence gap: the one missing fact that "
    "would most change which explanation is right. Do not name a fact an observation "
    "already states.\n"
    "4. Choose at most ONE probe from the menu that can retrieve evidence for that gap, "
    "or \"none\" if no listed probe can, or if the evidence already decides. Never choose "
    "a probe because it has not been run yet.\n"
    "5. Give a disposition. \"abstain\" is allowed only while a probe on the menu could "
    "still change the answer. When you answer \"none\", or no listed probe would change "
    "it, you must decide: \"malicious\" or \"benign\", whichever the observed rows "
    "support better, and your explanations must say why the other is weaker.\n"
    "\n"
    "Rules. Do not restate a detector's sentence as an explanation. Do not assert what no "
    "observation shows: no attacker, exfiltration, command-and-control or intent unless "
    "an observation shows it. Do not import a story from outside the observations (no "
    "'stale password', 'service account', 'scanner' or 'maintenance' unless a row shows "
    "it). When new evidence arrives, cite it where it bears on an explanation, drop what "
    "it contradicts, and say what it confirmed. Keep statements short and specific: name "
    "hosts, accounts, commands and times.\n"
    "\n"
    "What counts as a contribution (shapes only; the content is always this case's):\n"
    "- BAD: an explanation that repeats the rule's own sentence, or a generic story "
    "(\"credentials were guessed\", \"an admin was doing maintenance\") with no row "
    "named.\n"
    "- BAD: a claim about something no observation shows.\n"
    "- GOOD: a statement that names a specific row, what it shows, and how its timing or "
    "source or command bears on the choice between explanations, citing that row's id.\n"
    "- GOOD: a benign explanation grounded in an observed detail (the source host, the "
    "spacing, the command run, who owns the host) rather than in what is usually benign.\n"
    "- GOOD: a decision, once the retrieved rows favour one side, that says which row "
    "decided it.\n"
    "\n"
    "Respond with JSON only, in this shape:\n"
    "{\"explanations\": [{\"label\": \"malicious|benign|insufficient\", \"statement\": "
    "\"...\", \"evidence\": [\"<event id>\"]}], \"evidence_gap\": \"...\", "
    "\"next_probe\": \"P<n>|none\", \"probe_reason\": \"...\", "
    "\"disposition\": \"malicious|benign|abstain\"}"
)

INVESTIGATOR_USER_TEMPLATE = """Case {case_id}: hosts {hosts}; accounts {accounts}; window {window}; rules fired {rules}.
Round {round} of {rounds}. Probes already run: {probes_run}.

Observations:
{observations}
{new_evidence}
Probe menu (choose at most one, or "none"):
{menu}
{previous}"""

NEW_EVIDENCE_TEMPLATE = """
NEW EVIDENCE from your last probe (not seen before this round; cite these ids where they bear on an explanation):
{observations}
"""

PREVIOUS_TEMPLATE = """
Your previous explanations. Rewrite them against the new evidence: cite the new ids that support or contradict each one, drop what is contradicted, and decide if no remaining probe would change the answer.
{explanations}
Previous disposition: {disposition}."""


def prompt_sha256(text: str) -> str:
    """The digest a round's prompt is recorded under, newline-normalised like the prompt
    hashes. An offline replay proves it rebuilt a Colab prompt byte for byte by matching it."""
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def prompt_hashes() -> dict[str, str]:
    """The strings this loop's model ever reads, hashed, plus the schema and bounds.

    Recorded in the local freeze beside the four orchestrator prompt hashes, and gated
    the same way: a run under different D1 prompts is a different experiment.
    """
    def sha(text: str) -> str:
        return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()

    bounds = json.dumps({
        "max_probes": MAX_PROBES, "max_explanations": MAX_EXPLANATIONS,
        "max_evidence_per_explanation": MAX_EVIDENCE_PER_EXPLANATION,
        "max_menu": MAX_MENU, "max_ids_shown": MAX_IDS_SHOWN,
        "max_rows_shown": MAX_ROWS_SHOWN, "max_tokens": INVESTIGATOR_MAX_TOKENS,
    }, sort_keys=True)
    return {
        "investigator_version": D1_PROMPT_VERSION,
        "investigator_system": sha(INVESTIGATOR_SYSTEM),
        "investigator_user_template": sha(INVESTIGATOR_USER_TEMPLATE),
        "investigator_previous_template": sha(PREVIOUS_TEMPLATE + NEW_EVIDENCE_TEMPLATE),
        "investigator_schema": sha(json.dumps(RESPONSE_SCHEMA, sort_keys=True)),
        "investigator_bounds": sha(bounds),
    }


# --------------------------------------------------------------------------------------
# Observations and probes
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Observation:
    """One thing the model is shown: a rendered tool result and the ids behind it."""

    ref: str
    kind: str
    text: str
    event_ids: tuple[str, ...] = ()
    shown_ids: tuple[str, ...] = ()
    """The ids actually rendered in ``text``; the model may cite only these."""


@dataclass(frozen=True)
class Probe:
    """One entry of the menu: a tool, its arguments, and what it is for."""

    tool: str
    arguments: dict[str, Any]
    retrieves: str
    use_when: str
    not_when: str
    ref: str = ""

    @property
    def key(self) -> str:
        return json.dumps([self.tool, self.arguments], sort_keys=True, default=str)

    def render(self) -> str:
        args = ", ".join(f"{k}={v!r}" for k, v in self.arguments.items() if v not in (None, ""))
        return (
            f"{self.ref} {self.tool}({args}): retrieves {self.retrieves}. "
            f"Use when {self.use_when}. Not for {self.not_when}."
        )


def _short_time(value: Any) -> str:
    if isinstance(value, datetime):
        return value.strftime("%m-%d %H:%M:%S")
    text = str(value or "")
    if "T" in text and len(text) >= 19:
        return text[5:19].replace("T", " ")
    return text


def head_tail(items: Sequence[Any], limit: int, tail: int = 3) -> tuple[list[Any], list[Any], int]:
    """Up to ``limit`` items as a head and a tail, and how many fell between.

    The tail matters more than the middle: a burst of failures ends with the success,
    and a case's cited rows end with the execution the burst led to. Showing only a head
    would hide exactly the rows an explanation has to cite.
    """
    items = list(items)
    if len(items) <= limit:
        return items, [], 0
    tail = min(tail, limit - 1)
    head = items[: limit - tail]
    back = items[len(items) - tail:]
    return head, back, len(items) - len(head) - len(back)


def _ids(ids: Sequence[str]) -> tuple[str, str]:
    """The rendered id list and the ids it shows. Elision is a count, never silent."""
    head, tail, dropped = head_tail([str(e) for e in ids], MAX_IDS_SHOWN)
    text = ", ".join(head)
    if dropped:
        text += f", +{dropped} more"
    if tail:
        text += ", " + ", ".join(tail)
    return text, tuple(head + tail)


def _clip(text: Any, limit: int = 140) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _row_line(row: dict[str, Any]) -> str:
    """One raw telemetry row, compact, by table shape."""
    kind = str(row.get("event_type", ""))
    when = _short_time(row.get("timestamp"))
    if kind == "logon":
        source = row.get("source_device") or row.get("source_ip") or "?"
        reason = f" ({row['failure_reason']})" if row.get("failure_reason") else ""
        return (
            f"{when} logon {row.get('action', '?')}{reason} for '{row.get('user', '?')}' on "
            f"{row.get('device', '?')} from {source}, type {row.get('logon_type', '?')}"
        )
    if kind == "process":
        return (
            f"{when} process {row.get('process_name', '?')} pid {row.get('process_id', '?')} "
            f"on {row.get('device', '?')} user '{row.get('user', '?')}' parent "
            f"{row.get('parent_process_name', '?')} cmd '{_clip(row.get('command_line'), 120)}'"
        )
    if kind == "network":
        return (
            f"{when} network {row.get('process_name', '?')} on {row.get('device', '?')} -> "
            f"{row.get('remote_ip', '?')}:{row.get('remote_port', '?')} {row.get('direction', '')}"
        )
    if kind == "control":
        outcome = row.get("outcome") or row.get("result") or row.get("error_code") or ""
        return (
            f"{when} control {row.get('actor', '?')} {row.get('verb', '?')} "
            f"{row.get('resource_type', '?')} {_clip(row.get('resource_name'), 60)}"
            + (f" [{outcome}]" if outcome else "")
            + (f" from {row['source_ip']}" if row.get("source_ip") else "")
        )
    return f"{when} {kind} " + _clip(json.dumps({k: v for k, v in row.items() if k != 'event_id'}, default=str), 120)


class ObservationLog:
    """The observations in order, with stable refs, and every id the model was shown."""

    def __init__(self) -> None:
        self.items: list[Observation] = []

    def add(self, kind: str, text: str, event_ids: Sequence[str], shown: Sequence[str]) -> Observation:
        observation = Observation(
            ref=f"O{len(self.items) + 1}", kind=kind, text=text,
            event_ids=tuple(str(e) for e in event_ids), shown_ids=tuple(str(e) for e in shown),
        )
        self.items.append(observation)
        return observation

    @property
    def shown_ids(self) -> set[str]:
        return {e for o in self.items for e in o.shown_ids}

    def render(self, items: Sequence[Observation] | None = None) -> str:
        return "\n".join(f"{o.ref} {o.text}" for o in (self.items if items is None else items))


# --------------------------------------------------------------------------------------
# The menu
# --------------------------------------------------------------------------------------


def build_menu(
    case: InvestigationCase,
    process_rows: Sequence[dict[str, Any]],
    children: Sequence[dict[str, Any]],
    destinations: Sequence[tuple[str, str]],
    already_run: set[str],
) -> list[Probe]:
    """The probes the model may choose from this round, in a fixed order.

    Built only from what the state already holds: process rows the case's evidence cites
    (through the seed's ``get_events`` call), children an earlier ``process_tree``
    returned, accounts and hosts the case names, and destinations an earlier
    ``host_network_activity`` returned. A probe already run is not offered again.
    """
    probes: list[Probe] = []
    for row in process_rows[:3]:
        probes.append(Probe(
            "process_tree",
            {"device": row.get("device"), "pid": row.get("process_id"),
             "process_guid": row.get("process_guid") or ""},
            f"every CHILD process {row.get('process_name')} (pid {row.get('process_id')}) "
            f"on {row.get('device')} ran, with command lines and times, plus its parent "
            "chain",
            "you need to know what was actually done under this process after it "
            "started (discovery commands, a script, a tool); the parent shown in the "
            "cited row is already known",
            "authentication questions",
        ))
    for child in children[:3]:
        probes.append(Probe(
            "process_tree",
            {"device": child.get("device"), "pid": child.get("process_id"),
             "process_guid": child.get("process_guid") or ""},
            f"the children of {child.get('process_name')} (pid {child.get('process_id')}) on "
            f"{child.get('device')}: what that command went on to run",
            "a child's own command line is not enough to tell what it did",
            "anything outside that process",
        ))
    for user in case.users:
        if user.upper() in BUILTIN_ACCOUNTS:
            continue
        probes.append(Probe(
            "user_auth_history", {"user": user},
            f"every authentication event for account '{user}' across hosts: source host, "
            "logon type, success or failure, failure reason and timing",
            "you need to tell guessing from a stale or mistyped password, a locked "
            "account, or a scheduled job (source, spacing, logon type, what preceded it)",
            "what ran on a host",
        ))
    for device in case.devices:
        probes.append(Probe(
            "host_network_activity", {"device": device},
            f"outbound connections from {device}: destinations, counts and the processes "
            "that made them",
            "an explanation needs data leaving the host or contact with an outside "
            "address",
            "authentication or process lineage",
        ))
    for device, remote_ip in destinations[:2]:
        probes.append(Probe(
            "analyse_beacon", {"device": device, "remote_ip": remote_ip},
            f"timing regularity of {device} -> {remote_ip}",
            "a destination looks automated and regularity would separate a beacon from "
            "ordinary traffic",
            "one-off connections",
        ))
    menu: list[Probe] = []
    seen: set[str] = set()
    for probe in probes:
        if probe.key in already_run or probe.key in seen:
            continue
        seen.add(probe.key)
        menu.append(probe)
        if len(menu) >= MAX_MENU:
            break
    return [
        Probe(p.tool, p.arguments, p.retrieves, p.use_when, p.not_when, ref=f"P{i + 1}")
        for i, p in enumerate(menu)
    ]


# --------------------------------------------------------------------------------------
# The model's answer
# --------------------------------------------------------------------------------------


@dataclass
class Explanation:
    label: str
    statement: str
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "statement": self.statement, "evidence": list(self.evidence)}


@dataclass
class Answer:
    """A parsed, bounded model reply. Anything off the schema is dropped, and counted."""

    explanations: list[Explanation] = field(default_factory=list)
    evidence_gap: str = ""
    next_probe: str = NO_PROBE
    probe_reason: str = ""
    disposition: str = "abstain"
    dropped: dict[str, int] = field(default_factory=dict)

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(sorted(e.label for e in self.explanations))

    @property
    def has_benign(self) -> bool:
        return any(e.label == "benign" for e in self.explanations)


def parse_answer(parsed: dict[str, Any]) -> Answer:
    """Read the model's JSON into an :class:`Answer`, applying every bound again."""
    answer = Answer()
    raw = parsed.get("explanations")
    if not isinstance(raw, list):
        raw = []
    if len(raw) > MAX_EXPLANATIONS:
        answer.dropped["explanations_over_limit"] = len(raw) - MAX_EXPLANATIONS
    for item in raw[:MAX_EXPLANATIONS]:
        if not isinstance(item, dict):
            answer.dropped["malformed"] = answer.dropped.get("malformed", 0) + 1
            continue
        label = str(item.get("label", "")).strip().lower()
        statement = str(item.get("statement", "")).strip()
        if label not in LABELS or not statement:
            answer.dropped["malformed"] = answer.dropped.get("malformed", 0) + 1
            continue
        evidence = item.get("evidence") or []
        if not isinstance(evidence, list):
            evidence = []
        ids = [str(e).strip() for e in evidence if str(e).strip()]
        if len(ids) > MAX_EVIDENCE_PER_EXPLANATION:
            answer.dropped["evidence_over_limit"] = (
                answer.dropped.get("evidence_over_limit", 0)
                + len(ids) - MAX_EVIDENCE_PER_EXPLANATION
            )
            ids = ids[:MAX_EVIDENCE_PER_EXPLANATION]
        answer.explanations.append(Explanation(label, _clip(statement, STATEMENT_CHARS), tuple(dict.fromkeys(ids))))
    answer.evidence_gap = _clip(parsed.get("evidence_gap", ""), STATEMENT_CHARS)
    probe = str(parsed.get("next_probe", NO_PROBE)).strip()
    answer.next_probe = probe.upper() if probe.upper().startswith("P") else NO_PROBE
    answer.probe_reason = _clip(parsed.get("probe_reason", ""), STATEMENT_CHARS)
    disposition = str(parsed.get("disposition", "abstain")).strip().lower()
    answer.disposition = disposition if disposition in DISPOSITIONS else "abstain"
    if disposition not in DISPOSITIONS:
        answer.dropped["disposition_invalid"] = 1
    return answer


# --------------------------------------------------------------------------------------
# The loop
# --------------------------------------------------------------------------------------


@dataclass
class InvestigatorConfig:
    max_probes: int = MAX_PROBES
    max_tokens: int = INVESTIGATOR_MAX_TOKENS
    max_steps: int = 8
    """The arm's step budget. The seed is one step and every probe is one more; the
    loop never exceeds it, whatever ``max_probes`` says."""
    time_budget_seconds: float | None = None
    token_budget: int | None = None
    reject_unretrieved: bool = False
    prompt_contract: bool = False
    """Opt-in behaviour, none of it in ``prompt_hashes()``: a wall-clock budget checked
    before every round and passed on as the request timeout; a token budget; and
    verification of the conclusion against the ids the model was shown instead of the
    silent trim. D1 v3 rows were produced with all three off."""


class D1Investigator:
    """The single bounded investigator. ``investigate(case)`` returns an
    :class:`~ath.agent.state.InvestigationState` the existing scorer reads unchanged."""

    def __init__(
        self,
        tools: ToolBox,
        verifier: ClaimVerifier,
        llm: LLMClient | None = None,
        config: InvestigatorConfig | None = None,
    ) -> None:
        self.tools = tools
        self.verifier = verifier
        self.llm = llm or NullLLM()
        self.config = config or InvestigatorConfig()

    # The scorer asks the orchestrator what was still eligible when the run stopped.
    # Nothing here is "eligible" in that sense: the loop stops by its own bounds.
    def eligible(self, state: InvestigationState) -> list[tuple[Any, str]]:
        return []

    # -- seed -----------------------------------------------------------------------

    def _seed(self, state: InvestigationState, log: ObservationLog) -> tuple[list[dict[str, Any]], AgentResult]:
        case = state.case
        agent = f"{FAMILY}:seed"
        first_call = len(self.tools.calls)
        claims: list[Claim] = []
        notes: list[str] = []
        process_rows: list[dict[str, Any]] = []

        for finding in case.findings:
            payload = self.tools.get_finding(finding.finding_id, agent=agent)
            if payload.get("refused") or payload.get("error"):
                notes.append(f"{finding.finding_id}: not retrieved ({payload.get('reason') or payload.get('error')})")
                continue
            event_ids = tuple(str(e) for e in payload.get("event_ids", ()))
            if not event_ids:
                continue
            claims.append(Claim(
                claim_type=ClaimType.FACT,
                statement=(
                    f"{payload['rule_id']} ({payload['severity']}) on {payload['device']} "
                    f"under account {payload['user']}: {payload['title']}. {payload['reason']}"
                ),
                evidence_ids=event_ids, source="detector", agent=agent,
            ))
            ids_text, shown = _ids(event_ids)
            fps = payload.get("false_positives") or ()
            benign_causes = f" Known benign causes: {'; '.join(str(f) for f in fps[:3])}" if fps else ""
            log.add(
                "finding",
                f"[detector {payload['rule_id']} {payload['severity']}] {payload['device']} / "
                f"'{payload['user']}': {payload['title']}. {_clip(payload['reason'], 420)}"
                f"{benign_causes} (ids: {ids_text})",
                event_ids, shown,
            )

        wanted = list(case.event_ids)
        events = self.tools.get_events(wanted, agent=agent)
        rows = events.get("events", []) if not events.get("refused") else []
        if rows:
            ids = tuple(str(r["event_id"]) for r in rows)
            claims.append(Claim(
                claim_type=ClaimType.FACT,
                statement=(
                    f"The case's cited telemetry comprises {len(rows)} of {len(wanted)} "
                    f"event(s), from {rows[0]['timestamp']} to {rows[-1]['timestamp']}."
                ),
                evidence_ids=ids, source="tool", agent=agent,
            ))
            process_rows = [r for r in rows if r.get("event_type") == "process"]
            head, tail, dropped = head_tail(rows, MAX_ROWS_SHOWN)
            lines = [f"[{r['event_id']}] {_row_line(r)}" for r in head]
            if dropped:
                lines.append(f"... {dropped} more cited rows not shown ...")
            lines += [f"[{r['event_id']}] {_row_line(r)}" for r in tail]
            log.add(
                "events",
                f"[cited rows, {len(rows)} of {len(wanted)}, in time order]\n  " + "\n  ".join(lines),
                ids, tuple(str(r["event_id"]) for r in head + tail),
            )
        elif events.get("refused"):
            notes.append("get_events refused: tool budget exhausted before the seed finished")

        for technique in sorted({m.technique_id for m in case.mappings})[:6]:
            details = self.tools.lookup_technique(technique, agent=agent)
            if details.get("error") or details.get("refused"):
                continue
            mappings = [m for m in case.mappings if m.technique_id == technique]
            evidence = tuple(sorted({e for m in mappings for e in m.evidence_ids}))
            if not evidence:
                continue
            claims.append(Claim(
                claim_type=ClaimType.FACT,
                statement=(
                    f"{details['technique_id']} ({details['name']}) is catalogued under "
                    f"{', '.join(details['tactics'])} and is mapped to this case by "
                    f"{', '.join(sorted({m.rule_id for m in mappings}))}."
                ),
                evidence_ids=evidence, source="mitre", agent=agent,
            ))

        calls = tuple(c for c in self.tools.calls[first_call:] if c.agent == agent)
        return process_rows, AgentResult(
            agent=agent, ran_because="seed: the case's own findings, cited rows and mapped techniques",
            claims=tuple(claims), tool_calls=calls, notes=tuple(notes),
        )

    # -- probes ---------------------------------------------------------------------

    # A profile that wraps recorded values in untrusted envelopes may have the contract
    # check skip them. Off for every existing profile, which is checked exactly as before.
    contract_ignores_untrusted = False

    def _menu(
        self, state: InvestigationState, case: InvestigationCase,
        process_rows: Sequence[dict[str, Any]], children: Sequence[dict[str, Any]],
        destinations: Sequence[tuple[str, str]], already_run: set[str],
    ) -> list[Probe]:
        """The probe menu for this round. A hook so a profile can offer more probes;
        the base investigator offers exactly :func:`build_menu`."""
        return build_menu(case, process_rows, children, destinations, already_run)

    def _run_probe(
        self, state: InvestigationState, probe: Probe, log: ObservationLog, reason: str,
    ) -> tuple[AgentResult, list[dict[str, Any]], list[tuple[str, str]], tuple[str, ...]]:
        """Run one probe; return its step, any children and destinations it exposed, and
        the ids it returned."""
        agent = f"{FAMILY}:probe"
        first_call = len(self.tools.calls)
        claims: list[Claim] = []
        notes: list[str] = []
        children: list[dict[str, Any]] = []
        destinations: list[tuple[str, str]] = []
        returned: tuple[str, ...] = ()
        args = dict(probe.arguments)

        if probe.tool == "process_tree":
            tree = self.tools.process_tree(
                str(args["device"]), args.get("pid"), agent=agent,
                process_guid=str(args.get("process_guid") or ""),
            )
            if tree.get("refused"):
                notes.append("process_tree refused: tool budget exhausted")
            elif tree["resolution"] == "ambiguous_pid":
                cands = tree["candidates"]
                ids = tuple(c["event_id"] for c in cands)
                text = (
                    f"[process_tree {args['device']} pid {args.get('pid')}] pid was held by "
                    f"{len(cands)} process instances; no single lineage. Candidates: "
                    + "; ".join(f"[{c['event_id']}] {_short_time(c['timestamp'])} {c['process_name']} '{_clip(c['command_line'], 80)}'" for c in cands[:MAX_ROWS_SHOWN])
                )
                _, shown = _ids(ids)
                log.add("process_tree", text, ids, shown)
                notes.append(text)
            elif not tree["ancestry"]:
                text = f"[process_tree {args['device']} pid {args.get('pid')}] no lineage could be reconstructed"
                log.add("process_tree", text, (), ())
                notes.append(text)
            else:
                ancestry, kids = tree["ancestry"], tree["children"]
                leaf = ancestry[0]
                chain = " -> ".join([ancestry[-1]["parent_process_name"]] + [a["process_name"] for a in reversed(ancestry)])
                ids = tuple([a["event_id"] for a in ancestry] + [c["event_id"] for c in kids])
                claims.append(Claim(
                    claim_type=ClaimType.FACT,
                    statement=(
                        f"On {args['device']}, {leaf['process_name']} (PID {leaf['process_id']}) ran under "
                        f"account {leaf['user']} with execution chain {chain}"
                        + (f", spawning {len(kids)} child process(es): "
                           + ", ".join(sorted({c['process_name'] for c in kids})) if kids else ", spawning no observed child process")
                        + f". Resolution: {tree['resolution']}."
                    ),
                    evidence_ids=ids, source="tool", agent=agent,
                ))
                kid_lines = [
                    f"[{c['event_id']}] {_short_time(c['timestamp'])} {c['process_name']} pid {c['process_id']} cmd '{_clip(c['command_line'], 120)}'"
                    for c in kids[:MAX_ROWS_SHOWN]
                ]
                more = f"; +{len(kids) - MAX_ROWS_SHOWN} more children" if len(kids) > MAX_ROWS_SHOWN else ""
                text = (
                    f"[process_tree {args['device']} {leaf['process_name']} pid {leaf['process_id']}] "
                    f"chain {chain}; user '{leaf['user']}'; started {_short_time(leaf['timestamp'])}; "
                    f"cmd '{_clip(leaf['command_line'], 120)}' [{leaf['event_id']}]. "
                    + (f"Children ({len(kids)}): " + "; ".join(kid_lines) + more if kids else "No child process observed.")
                )
                shown = tuple([leaf["event_id"]] + [c["event_id"] for c in kids[:MAX_ROWS_SHOWN]])
                log.add("process_tree", text, ids, shown)
                children = [{**c, "device": args["device"]} for c in kids]
                returned = ids

        elif probe.tool == "user_auth_history":
            history = self.tools.user_auth_history(str(args["user"]), agent=agent)
            summary = history.get("summary") or {}
            if history.get("refused"):
                notes.append("user_auth_history refused: tool budget exhausted")
            elif not summary:
                text = f"[user_auth_history '{args['user']}'] no authentication telemetry for this account"
                log.add("user_auth_history", text, (), ())
                notes.append(text)
            else:
                events = history["events"]
                ids = tuple(str(e["event_id"]) for e in events)
                claims.append(Claim(
                    claim_type=ClaimType.FACT,
                    statement=(
                        f"Account '{args['user']}' has {summary['total']} authentication event(s) "
                        f"({summary['failures']} failed, {summary['successes']} successful) across hosts "
                        f"{', '.join(summary['target_devices'])}, from source(s) "
                        f"{', '.join(summary['source_devices']) or 'none resolved'}."
                    ),
                    evidence_ids=ids, source="tool", agent=agent,
                ))
                head = events[:MAX_ROWS_SHOWN - 2]
                tail = events[len(head):][-2:] if len(events) > len(head) else []
                def line(e: dict[str, Any]) -> str:
                    return (
                        f"[{e['event_id']}] {_short_time(e['timestamp'])} {e['action']} on {e['device']} "
                        f"from {e.get('source_device') or e.get('source_ip') or '?'} ({e['logon_type']})"
                    )
                lines = [line(e) for e in head]
                gap = f"; ... {len(events) - len(head) - len(tail)} more ..." if len(events) > len(head) + len(tail) else ""
                lines_tail = [line(e) for e in tail]
                text = (
                    f"[user_auth_history '{args['user']}'] {summary['total']} events: {summary['failures']} failed, "
                    f"{summary['successes']} successful; targets {', '.join(summary['target_devices'])}; sources "
                    f"{', '.join(summary['source_devices']) or 'none resolved'}; types {', '.join(summary['logon_types'])}; "
                    f"span {_short_time(summary['first_seen'])}..{_short_time(summary['last_seen'])}. Sequence: "
                    + "; ".join(lines) + gap + ("; " + "; ".join(lines_tail) if lines_tail else "")
                )
                shown = tuple(str(e["event_id"]) for e in head + tail)
                log.add("user_auth_history", text, ids, shown)
                returned = ids

        elif probe.tool == "host_network_activity":
            activity = self.tools.host_network_activity(str(args["device"]), agent=agent)
            ids = tuple(str(e) for e in activity.get("event_ids", ()))
            if activity.get("refused"):
                notes.append("host_network_activity refused: tool budget exhausted")
            elif not ids:
                text = f"[host_network_activity {args['device']}] no outbound network telemetry for this host"
                log.add("host_network_activity", text, (), ())
                notes.append(text)
            else:
                dests = activity["destinations"]
                claims.append(Claim(
                    claim_type=ClaimType.FACT,
                    statement=(
                        f"{args['device']} made {activity['total']} outbound connection(s) to "
                        f"{len(dests)} destination(s); the most frequent are "
                        + ", ".join(f"{d['remote_ip']} ({d['connections']} via {d['process_name']})" for d in dests[:5]) + "."
                    ),
                    evidence_ids=ids, source="tool", agent=agent,
                ))
                ids_text, shown = _ids(ids)
                text = (
                    f"[host_network_activity {args['device']}] {activity['total']} outbound connections to "
                    f"{len(dests)} destinations; top: "
                    + "; ".join(f"{d['remote_ip']} x{d['connections']} via {d['process_name']} first {_short_time(d['first_seen'])}" for d in dests[:5])
                    + f" (ids: {ids_text})"
                )
                log.add("host_network_activity", text, ids, shown)
                destinations = [(str(args["device"]), str(d["remote_ip"])) for d in dests[:3]]
                returned = ids

        elif probe.tool == "analyse_beacon":
            beacon = self.tools.analyse_beacon(str(args["device"]), str(args["remote_ip"]), agent=agent)
            ids = tuple(str(e) for e in beacon.get("event_ids", ()))
            if beacon.get("refused"):
                notes.append("analyse_beacon refused: tool budget exhausted")
            else:
                if beacon.get("regular") is not None and ids:
                    claims.append(Claim(
                        claim_type=ClaimType.FACT,
                        statement=(
                            f"{args['device']} -> {args['remote_ip']}: {beacon.get('samples', 0)} connection(s), "
                            f"{beacon.get('interarrival_count', 0)} interval(s), "
                            + (f"median {beacon['median_interval_seconds']} s, robust cv {beacon['robust_cv']}, "
                               f"{'regular' if beacon['regular'] else 'irregular'}" if "median_interval_seconds" in beacon
                               else str(beacon.get("reason", "")))
                            + "."
                        ),
                        evidence_ids=ids, source="tool", agent=agent,
                    ))
                ids_text, shown = _ids(ids)
                text = f"[analyse_beacon {args['device']} -> {args['remote_ip']}] " + _clip(
                    json.dumps({k: v for k, v in beacon.items() if k != "event_ids"}, default=str), 240,
                ) + (f" (ids: {ids_text})" if ids else "")
                log.add("analyse_beacon", text, ids, shown)
                returned = ids
        else:  # pragma: no cover -- the menu only offers the tools above
            notes.append(f"unknown probe tool {probe.tool!r}")

        calls = tuple(c for c in self.tools.calls[first_call:] if c.agent == agent)
        result = AgentResult(
            agent=agent, ran_because=f"probe {probe.ref} {probe.tool}: {reason or 'chosen by the model'}",
            claims=tuple(claims), tool_calls=calls, notes=tuple(notes),
        )
        return result, children, destinations, returned

    # -- the model ------------------------------------------------------------------

    def _ask(
        self, state: InvestigationState, log: ObservationLog, menu: Sequence[Probe],
        round_index: int, probes_run: Sequence[str], previous: Answer | None,
        new_since: int = 0,
    ) -> tuple[Answer | None, dict[str, Any]]:
        case = state.case
        previous_text = ""
        fresh = log.items[new_since:] if previous is not None else []
        new_evidence = (
            NEW_EVIDENCE_TEMPLATE.format(observations=log.render(fresh)) if fresh
            else ("\nNEW EVIDENCE from your last probe: none returned.\n" if previous is not None else "")
        )
        if previous is not None:
            previous_text = PREVIOUS_TEMPLATE.format(
                explanations="\n".join(
                    f"- [{e.label}] {e.statement}" + (f" (evidence: {', '.join(e.evidence)})" if e.evidence else "")
                    for e in previous.explanations
                ) or "- (none)",
                disposition=previous.disposition,
            )
        prompt = INVESTIGATOR_USER_TEMPLATE.format(
            case_id=case.case_id,
            hosts=", ".join(case.devices) or "none named",
            accounts=", ".join(case.users) or "none named",
            window=f"{_short_time(case.start_time)}..{_short_time(case.end_time)}",
            rules=", ".join(case.rule_ids),
            round=round_index + 1, rounds=self.config.max_probes + 1,
            probes_run=", ".join(probes_run) or "none",
            observations=log.render(log.items[:new_since] if fresh else log.items),
            new_evidence=new_evidence,
            menu="\n".join(p.render() for p in menu) or "(no probe applies)",
            previous=previous_text,
        )
        violations = (check_prompt_contract(prompt, ignore_untrusted=self.contract_ignores_untrusted)
                      if self.config.prompt_contract else [])
        if violations:
            response = LLMResponse(
                error=f"prompt contract violation: names raw field(s) {', '.join(violations[:6])}",
                model=self.llm.name,
            )
        elif self.config.time_budget_seconds is None:
            response = self.llm.complete(INVESTIGATOR_SYSTEM, prompt, max_tokens=self.config.max_tokens)
        else:
            remaining = self.config.time_budget_seconds - (time.perf_counter() - self._started)
            response = self.llm.complete(
                INVESTIGATOR_SYSTEM, prompt, max_tokens=self.config.max_tokens,
                timeout_seconds=max(1.0, remaining),
            )
        record: dict[str, Any] = {
            "parse_ok": False, "truncated": bool(getattr(response, "truncated", False)),
            "error": response.error, "output_tokens": response.output_tokens,
            # Recorded before any early return: an unusable reply is the one a reader
            # most needs to see, and the prompt digest lets an offline replay prove it
            # rebuilt this round's prompt byte for byte.
            "raw": _clip(getattr(response, "text", "") or "", RAW_REPLY_CHARS),
            "prompt_sha256": prompt_sha256(prompt),
            "prompt_chars": len(prompt),
        }
        if not response.ok:
            state.llm_errors.append(response.error or "unknown error")
            state.plan_log.append(f"round {round_index + 1}: model call failed ({response.error})")
            return None, record
        if not response.parsed:
            state.note_unparseable("investigator")
            state.plan_log.append(f"round {round_index + 1}: model reply was not parseable JSON")
            return None, record
        answer = parse_answer(response.parsed)
        record["parse_ok"] = True
        record["dropped"] = dict(answer.dropped)
        return answer, record

    # -- claims from the final answer -------------------------------------------------

    def _conclude(self, state: InvestigationState, answer: Answer | None, log: ObservationLog) -> AgentResult:
        """The final answer's explanations as unverified claims, for the verifier.

        Citation discipline, in order:

        * an id the model was shown is cited as given;
        * an id it was **not** shown and that does not exist stays on the claim, so the
          verifier rejects the claim and the row's rejected count names a fabrication;
        * an id it was not shown but that happens to exist is dropped from the claim and
          counted as out-of-scope -- the same rule orchestrator synthesis applies.
        """
        agent = f"{FAMILY}:conclude"
        probes = len([r for r in state.results if r.agent.endswith(":probe")])
        if answer is None:
            return AgentResult(
                agent=agent, ran_because=f"no usable model answer after {probes} probe(s)",
                notes=("no usable model answer; nothing concluded",),
            )
        shown = log.shown_ids
        proposed: list[Claim] = []
        out_of_scope = 0
        for explanation in answer.explanations:
            ids = tuple(explanation.evidence)
            unseen = [e for e in ids if e not in shown]
            fabricated = [e for e in unseen if self.verifier.check(
                Claim(ClaimType.HYPOTHESIS, "probe", (e,), source="llm")) is not None]
            if unseen and not fabricated and not self.config.reject_unretrieved:
                out_of_scope += 1
                state.plan_log.append(
                    f"conclude: dropped {len(unseen)} cited id(s) the model was not shown: "
                    f"{', '.join(unseen[:3])}"
                )
                ids = tuple(e for e in ids if e in shown)
            statement = f"[{explanation.label}] {explanation.statement}"
            claim_type = ClaimType.INFERENCE if ids else ClaimType.HYPOTHESIS
            proposed.append(Claim(
                claim_type=claim_type, statement=statement, evidence_ids=ids,
                source="llm", agent=agent,
            ))
        state.plan_log.append(
            f"conclude: {len(proposed)} explanation(s) proposed, {out_of_scope} with "
            f"out-of-scope citations dropped; disposition {answer.disposition}"
        )
        return AgentResult(
            agent=agent, ran_because=f"final explanations after {probes} probe(s)",
            claims=tuple(proposed),
            notes=(f"disposition: {answer.disposition}", f"evidence gap: {answer.evidence_gap}"),
        )

    # -- the loop -------------------------------------------------------------------

    def investigate(self, case: InvestigationCase) -> InvestigationState:
        state = InvestigationState(case=case, max_steps=self.config.max_steps)
        state.llm_requested = self.llm.available
        state.status = InvestigationStatus.IN_PROGRESS
        self._started = time.perf_counter()
        tokens_at_start = getattr(self.llm, "tokens_used", None) or 0
        log = ObservationLog()
        diagnostics: dict[str, Any] = {
            "version": D1_PROMPT_VERSION, "rounds": [], "probes_run": [],
        }
        state.investigation = diagnostics

        process_rows, seed = self._seed(state, log)
        state.plan_log.append("step 1: investigator:seed -- findings, cited rows, techniques")
        self._verify_and_record(state, seed)

        children: list[dict[str, Any]] = []
        destinations: list[tuple[str, str]] = []
        already_run: set[str] = set()
        probes_run: list[str] = []
        case_ids = set(case.event_ids)
        new_ids_returned: set[str] = set()
        new_ids_shown: set[str] = set()
        previous: Answer | None = None
        last_answer: Answer | None = None
        stop_reason = ""

        if not self.llm.available:
            stop_reason = "no model available"
        new_since = len(log.items)
        for round_index in range(self.config.max_probes + 1):
            if stop_reason:
                break
            budget_hit = self._budget_spent(tokens_at_start)
            if budget_hit:
                state.llm_errors.append(budget_hit)
                stop_reason = budget_hit
                break
            menu = self._menu(state, case, process_rows, children, destinations, already_run)
            answer, record = self._ask(state, log, menu, round_index, probes_run, previous, new_since)
            new_since = len(log.items)
            round_record: dict[str, Any] = {
                "round": round_index + 1, "menu": [p.ref + ":" + p.tool for p in menu],
                **record,
            }
            if answer is None:
                round_record["chosen_probe"] = None
                diagnostics["rounds"].append(round_record)
                stop_reason = "model call unusable"
                break
            last_answer = answer
            round_record.update({
                "explanations": [e.to_dict() for e in answer.explanations],
                "labels": list(answer.labels),
                "benign_present": answer.has_benign,
                "evidence_gap": answer.evidence_gap,
                "disposition": answer.disposition,
                "labels_changed": previous is not None and answer.labels != previous.labels,
                "disposition_changed": previous is not None and answer.disposition != previous.disposition,
                "statements_changed": previous is not None and [e.statement for e in answer.explanations] != [e.statement for e in previous.explanations],
                "dropped_explanations": (
                    [e.statement for e in previous.explanations if e.statement not in {x.statement for x in answer.explanations}]
                    if previous is not None else []
                ),
            })
            previous = answer
            by_ref = {p.ref: p for p in menu}
            chosen = by_ref.get(answer.next_probe)
            if answer.next_probe != NO_PROBE and chosen is None:
                round_record["invalid_probe"] = answer.next_probe
            if chosen is None or round_index >= self.config.max_probes:
                round_record["chosen_probe"] = None
                round_record["tool_choice_reason"] = answer.probe_reason
                diagnostics["rounds"].append(round_record)
                stop_reason = (
                    "model chose no probe" if chosen is None else "probe budget spent"
                )
                break
            if state.step >= state.max_steps or self.tools.budget_exhausted:
                round_record["chosen_probe"] = None
                diagnostics["rounds"].append(round_record)
                stop_reason = "step or tool budget spent"
                break
            new_since = len(log.items)
            result, new_children, new_destinations, returned = self._run_probe(state, chosen, log, answer.probe_reason)
            state.plan_log.append(f"step {state.step + 1}: investigator:probe -- {chosen.ref} {chosen.tool}: {answer.probe_reason}")
            self._verify_and_record(state, result)
            already_run.add(chosen.key)
            probes_run.append(f"{chosen.ref} {chosen.tool}")
            children = [c for c in children + new_children if c.get("event_id")]
            destinations = destinations + [d for d in new_destinations if d not in destinations]
            fresh = {e for e in returned if e not in case_ids}
            new_ids_returned |= fresh
            # What the model can actually cite: a probe may return thousands of ids (an
            # account's whole history) of which the observation renders a bounded head
            # and tail. "returned" is the retrieval's size; "shown" is the model's view.
            shown_fresh = {e for o in log.items[new_since:] for e in o.shown_ids if e not in case_ids}
            new_ids_shown |= shown_fresh
            round_record.update({
                "chosen_probe": {"ref": chosen.ref, "tool": chosen.tool, "arguments": {k: v for k, v in chosen.arguments.items() if v not in (None, "")}},
                "tool_choice_reason": answer.probe_reason,
                "new_evidence_ids_returned": len(fresh),
                "new_evidence_ids_shown": len(shown_fresh),
                "evidence_ids_returned": len(returned),
            })
            diagnostics["rounds"].append(round_record)
            diagnostics["probes_run"].append(chosen.tool)

        conclusion = self._conclude(state, last_answer, log)
        verification = self.verifier.verify(
            list(conclusion.claims),
            retrieved=frozenset(log.shown_ids) if self.config.reject_unretrieved else None,
        )
        state.record(conclusion, verification.accepted, verification.rejected)
        accepted = verification.accepted
        state.plan_log.append(
            f"conclude: accepted {len(verification.accepted)}, rejected {len(verification.rejected)}"
        )
        state.status = InvestigationStatus.COMPLETE if last_answer is not None else InvestigationStatus.EXHAUSTED
        if state.step >= state.max_steps and stop_reason == "step or tool budget spent":
            state.status = InvestigationStatus.STEP_LIMIT
        if stop_reason.endswith("budget exhausted") or "budget exhausted (" in stop_reason:
            state.status = InvestigationStatus.BUDGET_LIMIT
        state.plan_log.append(f"stop -- {stop_reason or 'concluded'}")

        # -- the compact summary the dev metrics read -----------------------------------
        rounds = diagnostics["rounds"]
        first = rounds[0] if rounds else {}
        final_claims = [c for c in accepted if c.source == "llm"]
        used_outside = {e for c in final_claims for e in c.evidence_ids if e not in case_ids}
        after_probe = [
            r for i, r in enumerate(rounds)
            if i > 0 and rounds[i - 1].get("chosen_probe")
        ]
        diagnostics.update({
            "initial_hypothesis_count": len(first.get("explanations", [])) if first.get("parse_ok") else 0,
            "final_hypothesis_count": len(last_answer.explanations) if last_answer else 0,
            "benign_hypothesis_present_initial": bool(first.get("benign_present")),
            "benign_hypothesis_present_final": bool(last_answer.has_benign) if last_answer else False,
            "evidence_gap": first.get("evidence_gap", ""),
            "chosen_tool": (first.get("chosen_probe") or {}).get("tool"),
            "tool_choice_reason": first.get("tool_choice_reason", ""),
            "chosen_tools": list(diagnostics["probes_run"]),
            "trajectory": ["seed"] + list(diagnostics["probes_run"]),
            "new_evidence_ids_returned": len(new_ids_returned),
            "new_evidence_ids_shown": len(new_ids_shown),
            "new_evidence_ids_used": len(used_outside),
            "hypothesis_changed_after_tool": any(
                r.get("labels_changed") or r.get("disposition_changed") or r.get("statements_changed")
                for r in after_probe
            ),
            "labels_changed_after_tool": any(r.get("labels_changed") or r.get("disposition_changed") for r in after_probe),
            "abstained": (last_answer.disposition == "abstain") if last_answer else None,
            "final_disposition": last_answer.disposition if last_answer else None,
            "output_truncated": any(r.get("truncated") for r in rounds),
            "model_calls": len(rounds),
            "probes_run": list(diagnostics["probes_run"]),
            "stop_reason": stop_reason or "concluded",
            "menu_sizes": [len(r.get("menu", [])) for r in rounds],
        })
        logger.info(
            "%s: D1 finished (%s) after %d probe(s); disposition %s; %d model claim(s)",
            case.case_id, diagnostics["stop_reason"], len(diagnostics["probes_run"]),
            diagnostics["final_disposition"], len(final_claims),
        )
        return state

    _started: float = 0.0

    def _budget_spent(self, tokens_at_start: int) -> str | None:
        """Why the wall-clock or token budget is spent, or ``None``."""
        if self.config.time_budget_seconds is not None:
            elapsed = time.perf_counter() - self._started
            if elapsed >= self.config.time_budget_seconds:
                return f"time budget exhausted ({self.config.time_budget_seconds:.0f}s)"
        if self.config.token_budget is not None:
            now = getattr(self.llm, "tokens_used", None)
            if now is not None and now - tokens_at_start >= self.config.token_budget:
                return f"token budget exhausted ({now - tokens_at_start} of {self.config.token_budget})"
        return None

    def _verify_and_record(self, state: InvestigationState, result: AgentResult) -> None:
        verification = self.verifier.verify(list(result.claims))
        state.record(result, verification.accepted, verification.rejected)


def build_investigator(
    tools: ToolBox, verifier: ClaimVerifier, llm: LLMClient | None, *, max_steps: int = 8,
    max_probes: int = MAX_PROBES, max_tokens: int = INVESTIGATOR_MAX_TOKENS,
    time_budget_seconds: float | None = None, token_budget: int | None = None,
    reject_unretrieved: bool = False, prompt_contract: bool = False,
) -> D1Investigator:
    return D1Investigator(
        tools, verifier, llm=llm,
        config=InvestigatorConfig(
            max_probes=max_probes, max_tokens=max_tokens, max_steps=max_steps,
            time_budget_seconds=time_budget_seconds, token_budget=token_budget,
            reject_unretrieved=reject_unretrieved, prompt_contract=prompt_contract,
        ),
    )
