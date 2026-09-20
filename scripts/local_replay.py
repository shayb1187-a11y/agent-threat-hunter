"""Offline replay of the D1 loop on the real dev cases, with no model.

Why this exists
---------------
The D1 v2 smoke measured LINK-2 recovered 0 times while the shell's children were
retrieved and rendered in every case (``reports/local/dev/D1_AUDIT.md``, pass 1). A zero
has three possible owners -- the retrieval, the rendering, the scorer -- before the model
is one, and none of them needs a model to be ruled out. This script drives the real loop
(:func:`ath.evaluation.ablation.local.run_local_arm`, the same call ``local_ablation.py
run`` makes) over the real injected dev cases with an *oracle* client: a stand-in that
reads the prompt it is given and answers from what the prompt shows. It can cite only
ids the prompt rendered, exactly the discipline the model is under, and it knows which
logon and which child the link names. What it measures is the **ceiling of the
harness**: if the oracle's row recovers LINK-2, a model's zero is the model's.

It never writes a row. Its output is text (and, with ``--json``, a file under
``reports/local/`` only), so it can run on the laptop where no model may.

Paths (``--path``)
------------------
``link``       round 1 asks for the shell's ``process_tree``; the next round cites the
               link's logon and the first child it was shown, chooses no probe, decides.
``abstain``    one round, no probe: prints the seed prompt as the model first sees it.
``auth-first`` ``user_auth_history`` first, then the shell's ``process_tree``, then the
               link: checks the shell's tree is still offered after another probe, and
               that the child arrives as NEW EVIDENCE in the last round.

The manifest-hash caveat
------------------------
The dev manifest's telemetry digest differs between this laptop and Colab for byte-
identical cases (``D1_AUDIT.md``). So the replay builds its one-case manifest entry from
the bundle it loaded, never from ``MANIFEST.json``, and prints the committed digest
beside the recomputed one for information only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import local_manifest  # noqa: E402

from ath.agent.investigator import (  # noqa: E402
    NEW_EVIDENCE_TEMPLATE,
    prompt_sha256,
)
from ath.agent.llm import LLMResponse, TokenAccounting  # noqa: E402
from ath.evaluation.ablation import build_manifest, manifest_hash  # noqa: E402
from ath.evaluation.ablation.local import arm_d1, refuse_frozen_path, run_local_arm  # noqa: E402

PATHS: tuple[str, ...] = ("link", "abstain", "auth-first")

NEW_EVIDENCE_HEADING = NEW_EVIDENCE_TEMPLATE.strip().splitlines()[0].split("{")[0].strip()
"""The first words of the NEW EVIDENCE section, taken from the template so a rewording
of the template fails this script loudly rather than silently finding nothing."""

_ROUND = re.compile(r"^Round (\d+) of (\d+)\.", re.MULTILINE)
_MENU_LINE = re.compile(r"^(P\d+) (\w+)\((.*?)\): ", re.MULTILINE)
_SHORT_TIME = r"\d\d-\d\d \d\d:\d\d:\d\d"
_PROCESS_ROW = re.compile(rf"\[([^\]\s]+)\] {_SHORT_TIME} process (\S+) pid")
"""A cited process row as the seed renders it: ``[id] mm-dd hh:mm:ss process <name> pid``."""
_CHILD_ROW = re.compile(rf"\[([^\]\s]+)\] {_SHORT_TIME} (\S+) pid \d+ cmd ")
"""A child as ``process_tree`` renders it: ``[id] mm-dd hh:mm:ss <name> pid <n> cmd '...'``."""


# --------------------------------------------------------------------------------------
# The oracle
# --------------------------------------------------------------------------------------


def new_evidence_section(prompt: str) -> str:
    """The text of the NEW EVIDENCE section, or ``""`` when the prompt has none."""
    start = prompt.find(NEW_EVIDENCE_HEADING)
    if start < 0:
        return ""
    end = prompt.find("\nProbe menu", start)
    return prompt[start:end if end >= 0 else len(prompt)]


def children_shown(prompt: str) -> list[str]:
    """Child process ids rendered in the prompt's NEW EVIDENCE section, in order."""
    return [m.group(1) for m in _CHILD_ROW.finditer(new_evidence_section(prompt))]


def menu_ref(prompt: str, tool: str, needle: str = "") -> str | None:
    """The ``P<n>`` of the first menu line offering ``tool`` whose text has ``needle``."""
    for line in prompt.splitlines():
        match = _MENU_LINE.match(line)
        if match and match.group(2) == tool and needle in line:
            return match.group(1)
    return None


def shell_rows(prompt: str) -> list[str]:
    """Ids of the cited process rows the seed rendered (the service-launched shell)."""
    return [m.group(1) for m in _PROCESS_ROW.finditer(prompt)]


def round_of(prompt: str) -> tuple[int, int]:
    match = _ROUND.search(prompt)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def _reply(explanations: list[dict[str, Any]], *, gap: str, probe: str, reason: str, disposition: str) -> str:
    return json.dumps({
        "explanations": explanations, "evidence_gap": gap, "next_probe": probe,
        "probe_reason": reason, "disposition": disposition,
    })


class OracleLLM(TokenAccounting):
    """A prompt-reading stand-in for the model that knows which rows the link names.

    It cites an id only when the prompt it was given rendered that id, so a row it
    produces says what the harness *can* recover, never what it could if the model saw
    more than it does.
    """

    name = "replay-oracle"
    available = True

    def __init__(self, path: str, identity_id: str, endpoint_id: str | None) -> None:
        super().__init__()
        if path not in PATHS:
            raise ValueError(f"unknown path {path!r}; one of {PATHS}")
        self.path = path
        self.identity_id = identity_id
        self.endpoint_id = endpoint_id
        self.calls: list[tuple[str, str]] = []
        self.notes: list[str] = []

    def complete(self, system: str, prompt: str, max_tokens: int = 1024) -> LLMResponse:
        self.calls.append((system, prompt))
        text = self._answer(prompt)
        self._record_usage(None, None, model=self.name, stop_reason="end_turn", has_text=True)
        return LLMResponse(text=text, model=self.name, parsed=json.loads(text), stop_reason="end_turn")

    # -- the paths ------------------------------------------------------------------

    def _answer(self, prompt: str) -> str:
        if self.path == "abstain":
            return _reply(
                [{"label": "insufficient", "statement": "replay: no probe taken", "evidence": []}],
                gap="replay", probe="none", reason="", disposition="abstain",
            )
        children = children_shown(prompt)
        if children:
            return self._conclude(prompt, children)
        round_index, _ = round_of(prompt)
        if self.path == "auth-first" and round_index == 1:
            ref = menu_ref(prompt, "user_auth_history")
            if ref is not None:
                return self._probe(prompt, ref, "replay: the account's history first")
            self.notes.append("round 1: no user_auth_history probe offered; falling through to process_tree")
        ref = menu_ref(prompt, "process_tree", "cmd.exe") or menu_ref(prompt, "process_tree")
        if ref is None:
            self.notes.append(f"round {round_index}: no process_tree probe offered")
            return _reply(
                [{"label": "insufficient", "statement": "replay: no process_tree offered", "evidence": []}],
                gap="what ran under the shell", probe="none", reason="", disposition="abstain",
            )
        return self._probe(prompt, ref, "replay: what ran under the shell")

    def _probe(self, prompt: str, ref: str, reason: str) -> str:
        shells = shell_rows(prompt)
        cited = shells[:1]
        return _reply(
            [
                {"label": "malicious", "statement": "replay: a guessed credential then a service-launched shell", "evidence": cited},
                {"label": "benign", "statement": "replay: an administrative shell under a real session", "evidence": cited},
            ],
            gap="what ran under the shell", probe=ref, reason=reason, disposition="abstain",
        )

    def _conclude(self, prompt: str, children: list[str]) -> str:
        child = self.endpoint_id if self.endpoint_id in children else children[0]
        if self.endpoint_id is not None and self.endpoint_id not in children:
            self.notes.append(f"the link's child {self.endpoint_id} is not among the children shown: {children[:3]}")
        evidence = [child]
        if self.identity_id in prompt:
            evidence.insert(0, self.identity_id)
        else:
            self.notes.append(f"the link's logon {self.identity_id} is not in the prompt; citing the child only")
        return _reply(
            [{"label": "malicious", "statement": "replay: the logon explains the shell, and the shell ran this command", "evidence": evidence}],
            gap="none", probe="none", reason="", disposition="malicious",
        )


# --------------------------------------------------------------------------------------
# One case
# --------------------------------------------------------------------------------------


def replay_case(case_id: str, path: str) -> dict[str, Any]:
    """Load one injected dev case, run the loop under the oracle, return what was seen."""
    bundle = local_manifest.injected_dev_bundle(case_id)
    if len(bundle.cases) != 1:
        raise SystemExit(f"{bundle.name}: expected one case, formed {len(bundle.cases)}")
    label_block, links = local_manifest.injected_labels(case_id, bundle.telemetry)
    case = bundle.cases[0]
    entries = build_manifest(
        bundle.name, bundle.telemetry, [case],
        selection=f"replay: the single case reports/local/dev/cases/dedale_injected/{case_id}/ forms",
        labels={case.case_id: label_block},
    )
    entry = entries[0]
    digest = manifest_hash(entries)

    link_2 = next((l for l in links if l["link_id"].endswith("LINK-2")), None)
    link_1 = next((l for l in links if l["link_id"].endswith("LINK-1")), None)
    target = link_2 or link_1
    oracle = OracleLLM(
        path,
        identity_id=str(target["identity"]["event_id"]) if target else "",
        endpoint_id=str(link_2["endpoint"]["event_id"]) if link_2 else None,
    )
    arm = arm_d1("replay:none", llm_factory=lambda model: oracle)
    result = run_local_arm(
        arm, [entry], bundle.telemetry, bundle.cases,
        manifest_digest=digest, findings=bundle.findings, environment=bundle.environment,
        llm=oracle, scripted=True, links={entry.key: links},
    )[0]
    state = result.state
    investigation = state.get("investigation") or {}
    prompts = [prompt for _, prompt in oracle.calls]
    first = prompts[0] if prompts else ""
    child_round = next(
        (i + 1 for i, p in enumerate(prompts) if link_2 and link_2["endpoint"]["event_id"] in new_evidence_section(p)),
        None,
    )
    model_claims = [c for c in state.get("claims", []) if c.get("source") == "llm"]
    return {
        "case": case_id, "path": path, "corpus": bundle.name, "case_id": case.case_id,
        "manifest_hash_recomputed": digest,
        "links_defined": [l["link_id"] for l in links],
        "identity_id": target["identity"]["event_id"] if target else None,
        "endpoint_id_link_2": link_2["endpoint"]["event_id"] if link_2 else None,
        "identity_shown_after_seed": bool(target) and target["identity"]["event_id"] in first,
        "shell_probe_offered_first": menu_ref(first, "process_tree", "cmd.exe") if first else None,
        "child_in_new_evidence_round": child_round,
        "probes_run": list(investigation.get("probes_run") or []),
        "rounds": [
            {"round": r.get("round"), "prompt_sha256": r.get("prompt_sha256"), "prompt_chars": r.get("prompt_chars"),
             "chosen_probe": (r.get("chosen_probe") or {}).get("tool"), "new_evidence_ids_returned": r.get("new_evidence_ids_returned")}
            for r in investigation.get("rounds") or []
        ],
        "new_evidence_ids_used": investigation.get("new_evidence_ids_used"),
        "final_disposition": investigation.get("final_disposition"),
        "model_claims": [{"type": c["type"], "evidence_ids": c["evidence_ids"], "statement": c["statement"][:120]} for c in model_claims],
        "rejected_claims": len(state.get("rejected_claims") or []),
        "links": result.label_scores.get("links"),
        "links_error": result.label_scores.get("links_error"),
        "oracle_notes": list(oracle.notes),
        "prompts": prompts,
    }


# --------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------


def _print_case(seen: dict[str, Any], *, show_prompts: bool) -> None:
    print("=" * 96)
    print(f"{seen['corpus']}/{seen['case_id']}  path={seen['path']}  manifest(recomputed) {seen['manifest_hash_recomputed'][:12]}")
    print(f"  links defined: {', '.join(seen['links_defined']) or 'none'}")
    print(f"  identity id {seen['identity_id']} shown after seed: {seen['identity_shown_after_seed']}")
    print(f"  shell process_tree offered first as: {seen['shell_probe_offered_first']}")
    print(f"  LINK-2 child {seen['endpoint_id_link_2']} in NEW EVIDENCE at round: {seen['child_in_new_evidence_round']}")
    print(f"  probes run: {seen['probes_run']}; new ids used: {seen['new_evidence_ids_used']}; disposition: {seen['final_disposition']}")
    for r in seen["rounds"]:
        print(f"  round {r['round']}: prompt sha256 {str(r['prompt_sha256'])[:16]} ({r['prompt_chars']} chars), chose {r['chosen_probe']}, new ids returned {r['new_evidence_ids_returned']}")
    for c in seen["model_claims"]:
        print(f"  claim {c['type']} cites {c['evidence_ids']}: {c['statement']}")
    print(f"  rejected claims: {seen['rejected_claims']}; links: {seen['links']}" + (f"; links_error: {seen['links_error']}" if seen.get("links_error") else ""))
    for note in seen["oracle_notes"]:
        print(f"  NOTE {note}")
    for i, prompt in enumerate(seen["prompts"], 1):
        if show_prompts:
            print(f"\n  --- round {i} prompt ({len(prompt)} chars, sha256 {prompt_sha256(prompt)[:16]}) ---")
            print("  " + prompt.replace("\n", "\n  "))
        else:
            section = new_evidence_section(prompt)
            if section:
                print(f"\n  --- round {i} NEW EVIDENCE ---")
                print("  " + section.strip().replace("\n", "\n  "))
            menu = [line for line in prompt.splitlines() if _MENU_LINE.match(line)]
            print(f"  --- round {i} menu ({len(menu)}) ---")
            for line in menu:
                print("  " + line[:160])


def _summary(seen_all: Sequence[dict[str, Any]]) -> tuple[list[str], int]:
    lines = ["", "| case | path | identity shown | child round | probes | LINK-1 | LINK-2 | rejected |", "| --- | --- | --- | --- | --- | --- | --- | ---: |"]
    missed = 0
    for s in seen_all:
        links = s["links"] or {}
        l1 = next((v for k, v in links.items() if k.endswith("LINK-1")), None)
        l2 = next((v for k, v in links.items() if k.endswith("LINK-2")), None)
        if s["path"] == "link" and l2 is False:
            missed += 1
        lines.append(
            f"| {s['case']} | {s['path']} | {s['identity_shown_after_seed']} | {s['child_in_new_evidence_round']} | "
            f"{','.join(s['probes_run']) or '-'} | {'-' if l1 is None else l1} | {'-' if l2 is None else l2} | {s['rejected_claims']} |"
        )
    return lines, missed


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--path", choices=PATHS, default="link")
    parser.add_argument("--only", nargs="*", default=None, metavar="CASE", help="injected dev case ids (V1 ...); default all")
    parser.add_argument("--prompts", action="store_true", help="print every round's full prompt")
    parser.add_argument("--json", type=Path, default=None, help="also write everything seen (prompts included) here")
    args = parser.parse_args(argv)

    if args.json is not None:
        refuse_frozen_path(args.json, ROOT)
    committed = None
    try:
        payload, _, _ = local_manifest.read_manifest()
        committed = str(payload.get("manifest_hash"))[:12]
    except SystemExit:
        pass
    if committed:
        print(f"committed dev manifest {committed} (informational; the replay pins the live load, see the module docstring)")

    wanted = list(args.only) if args.only else list(local_manifest.DEV_INJECTED_IDS)
    seen_all: list[dict[str, Any]] = []
    for case_id in wanted:
        seen = replay_case(case_id, args.path)
        seen_all.append(seen)
        _print_case(seen, show_prompts=args.prompts)

    lines, missed = _summary(seen_all)
    print("\n".join(lines))
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(seen_all, indent=2, default=str) + "\n", encoding="utf-8")
        print(f"wrote {args.json}")
    if args.path == "link" and missed:
        print(f"\nFAIL: {missed} case(s) defined a LINK-2 the oracle path did not recover; the harness, not a model, lost it.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
