"""Operational D1 extension: typed premises and deterministically rendered observations.

The original D1 prompts, schema, parser and experiment arms are unchanged.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import replace

from ath.agent.claims import Claim, ClaimType, ClaimVerifier
from ath.agent.evidence import (
    AssertionKind,
    EvidenceAssertion,
    EvidenceStatus,
    EvidenceVerifier,
)
from ath.agent.investigator import RESPONSE_SCHEMA, D1Investigator
from ath.agent.state import AgentResult, InvestigationState
from ath.telemetry.loader import Telemetry

EVIDENCE_VERSION = "structured-evidence-v1"
MAX_ASSERTIONS = 6
# Pinned: the v2 schema and parser accept exactly these kinds, whatever AssertionKind
# grows later, so operational-v2 freezes keep their schema digest and behaviour.
V2_ASSERTION_KINDS = ("auth_outcome", "process_identity", "same_process", "parent_child", "before")
EVIDENCE_RESPONSE_SCHEMA = deepcopy(RESPONSE_SCHEMA)
_explanation = EVIDENCE_RESPONSE_SCHEMA["properties"]["explanations"]["items"]
_explanation["required"].append("assertions")
_explanation["properties"]["assertions"] = {
    "type": "array", "maxItems": MAX_ASSERTIONS,
    "items": {
        "type": "object",
        "properties": {
            "kind": {"type": "string", "enum": list(V2_ASSERTION_KINDS)},
            "event_id": {"type": "string", "maxLength": 512},
            "other_event_id": {"type": "string", "maxLength": 512},
            "expected": {"type": "string", "maxLength": 512},
        },
        "required": ["kind", "event_id"], "additionalProperties": False,
    },
}

EVIDENCE_INSTRUCTIONS = """
Each explanation MUST also contain an assertions array (at most 6 typed premises).
Use only these predicates; all referenced ids must also be in that explanation's evidence:
- auth_outcome: event_id plus expected='success' or 'failure'.
- process_identity: event_id plus expected=the source-qualified instance identity, ONLY if shown.
- same_process: event_id and other_event_id describe the same process instance.
- parent_child: event_id is the parent's process event; other_event_id is the child's.
- before: event_id occurs strictly before other_event_id by recorded timestamp, NOT causation.
Do not guess source identities or infer a process instance from PID equality. If a needed
predicate cannot be supported, explain the evidence gap and abstain or retrieve more.
An empty assertions array means the explanation has reference checks only. Free-text
attack interpretations remain inferences even when their typed premises are supported.
Example shape only: {"label":"insufficient","statement":"...","evidence":[],"assertions":[]}.
""".strip()


class _EvidenceClient:
    def __init__(self, client):
        self.client = client
        self.last = None
        self.prompt_hash = ""
        self.system_hash = ""

    @property
    def available(self):
        return self.client.available

    @property
    def name(self):
        return self.client.name

    @property
    def tokens_used(self):
        return self.client.tokens_used

    def complete(self, system, prompt, max_tokens=1024, timeout_seconds=None):
        system = system + "\n\n" + EVIDENCE_INSTRUCTIONS
        self.prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        self.system_hash = hashlib.sha256(system.encode("utf-8")).hexdigest()
        self.last = None
        response = self.client.complete(system, prompt, max_tokens, timeout_seconds)
        if not response.ok:
            return response
        try:
            groups = []
            for item in response.parsed["explanations"]:
                raw = item.get("assertions")
                if not isinstance(raw, list) or len(raw) > MAX_ASSERTIONS:
                    raise ValueError("each explanation requires at most six assertions")
                parsed = tuple(EvidenceAssertion.from_dict(a) for a in raw)
                if any(a.kind.value not in V2_ASSERTION_KINDS for a in parsed):
                    raise ValueError("assertion kind is not part of the v2 evidence contract")
                groups.append(parsed)
            self.last = groups
        except (KeyError, TypeError, ValueError):
            return replace(response, error="invalid structured evidence assertions")
        return response


class EvidenceInvestigator(D1Investigator):
    """Reuse D1's loop while carrying predicates from each answer to its claims."""

    def __init__(self, tools, verifier, llm, config):
        super().__init__(tools, verifier, llm=_EvidenceClient(llm), config=config)
        self._assertions = []

    def _ask(self, state, log, menu, *args, **kwargs):
        # D1's menu exposes an internal argument name when source identity exists.
        # Change only its presentation; the loop executes the original bound probe.
        presented = [replace(probe, arguments={
            "instance" if key == "process_guid" else key: value
            for key, value in probe.arguments.items()
        }) for probe in menu]
        answer, record = super()._ask(state, log, presented, *args, **kwargs)
        record["system_sha256"] = self.llm.system_hash
        record["evidence_version"] = EVIDENCE_VERSION
        if answer is not None:
            groups = self.llm.last or []
            # A tolerant parser may discard explanations; do not attach predicates
            # from a different position to the remaining prose.
            if any(answer.dropped.values()) or len(groups) != len(answer.explanations):
                state.llm_errors.append("structured explanation parsing changed the answer")
                return None, {**record, "error": "structured explanation parsing changed the answer"}
            self._assertions = groups
            record["assertions"] = [[a.to_dict() for a in group] for group in groups]
        return answer, record

    def _conclude(self, state, answer, log):
        result = super()._conclude(state, answer, log)
        return replace(result, claims=tuple(
            replace(claim, assertions=assertions)
            for claim, assertions in zip(result.claims, self._assertions)
        ))


def finalise_evidence(
    state: InvestigationState, telemetry: Telemetry, verifier: ClaimVerifier, limit: int,
) -> None:
    """Separate unchecked summaries from validated, template-rendered observations.

    Only evidence already returned by row-bearing tools can add observations. The
    bounded list is disclosed; an absent observation is never evidence of absence.
    """
    evidence = EvidenceVerifier(telemetry)
    reports = []
    for claim in state.claims + [item.claim for item in state.rejected_claims]:
        if claim.assertions:
            reports.append({
                "statement": claim.statement, "source": claim.source,
                "reference_error": verifier.check(replace(claim, assertions=())),
                "assertion_error": verifier.check(claim),
                "checks": [check.to_dict() for check in verifier.evidence_checks(claim)],
                "interpretation_verified": False,
            })

    def separate(claim):
        if claim.claim_type is ClaimType.FACT and not claim.assertions:
            return replace(claim, claim_type=ClaimType.INFERENCE,
                           statement="Unverified summary: " + claim.statement)
        return claim

    changed = sum(c.claim_type is ClaimType.FACT and not c.assertions for c in state.claims)
    state.claims = [separate(c) for c in state.claims]
    state.results = [replace(r, claims=tuple(separate(c) for c in r.claims)) for r in state.results]
    candidates = list(dict.fromkeys(a for c in state.claims for a in c.assertions))
    ids = set()
    for call in state.tool_calls:
        if not call.refused and call.tool in ("get_events", "process_tree", "user_auth_history", "search_processes",
                                                  "actor_control_history", "resource_control_history", "identity_grants"):
            ids.update(call.shown_event_ids if call.truncated else call.event_ids)
    selected = sorted(ids)[:limit]
    process_rows = []
    for event_id in selected:
        row, _ = evidence.row(event_id)
        if row is None:
            continue
        if row["event_type"] == "logon" and row.get("action") in ("success", "failure"):
            candidates.append(EvidenceAssertion(AssertionKind.AUTH_OUTCOME, event_id, expected=row["action"]))
        elif row["event_type"] in ("process", "network"):
            if row["event_type"] == "process":
                process_rows.append(row)
            try:
                candidates.append(EvidenceAssertion(AssertionKind.PROCESS_IDENTITY, event_id,
                                                     expected=row.get("process_guid", "")))
            except ValueError:
                pass  # No source identity: retain the gap, never promote the PID.
    parents = {}
    for row in process_rows:
        identity = row.get("process_guid")
        if isinstance(identity, str) and identity:
            parents.setdefault((row["device"], identity), []).append(row["event_id"])
    for row in process_rows:
        matches = parents.get((row["device"], row.get("parent_process_guid")), [])
        if len(matches) == 1 and matches[0] != row["event_id"]:
            candidates.append(EvidenceAssertion(AssertionKind.PARENT_CHILD, matches[0], row["event_id"]))
    observations = []
    for assertion in dict.fromkeys(candidates):
        check = evidence.check(assertion)
        if check.status is not EvidenceStatus.SUPPORTED:
            continue
        claim = Claim(ClaimType.FACT, assertion.render(), assertion.event_ids,
                      source="telemetry", agent="evidence_verifier", assertions=(assertion,))
        if verifier.check(claim) is None:
            observations.append(claim)
    # Verification adds no tool calls or investigation steps.
    state.claims.extend(observations)
    state.results.append(AgentResult(
        agent="evidence_verifier", ran_because="validate typed observations against cited telemetry",
        claims=tuple(observations),
    ))
    state.investigation["evidence_verification"] = {
        "version": EVIDENCE_VERSION,
        "schema_sha256": hashlib.sha256(json.dumps(EVIDENCE_RESPONSE_SCHEMA, sort_keys=True).encode()).hexdigest(),
        "claims": reports, "observations_verified": len(observations),
        "summaries_reclassified": changed, "observation_events_considered": len(selected),
        "observation_events_omitted": max(0, len(ids) - len(selected)),
        "interpretation_verified": False,
    }
    state.plan_log.append(f"evidence verification: {len(observations)} checked observations; {changed} summaries reclassified")
