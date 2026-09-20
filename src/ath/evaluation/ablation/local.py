"""The local-model tier of the ablation: a D1 arm, a resumable row store, a RAM guard,
and a freeze that records the model rather than the credential.

Why a sibling module and not an edit to :mod:`ath.evaluation.ablation.arms`
----------------------------------------------------------------------------
``arms.py`` is one of the three files whose hash the M19b freeze gates on, and the
M19b Phase 8 run has not happened yet. A D1 arm added there would change that hash for a
run that has nothing to do with D1. So every local addition lives here: it *reuses*
:class:`~ath.evaluation.ablation.arms.ArmConfig`, :func:`~ath.evaluation.ablation.arms.arm_b`
and :func:`~ath.evaluation.ablation.arms.run_arm` unchanged, and registers its arms in
its own :data:`LOCAL_ARM_BUILDERS`. ``tests/test_frozen_surface_pin.py`` is what turns
that intention into something that fails.

The D1 arm
-----------
The first D1 preview ran arm B's architecture (seven facets of one generalist, walked to
exhaustion, then one synthesis pass) on the local model and measured a detector narrator:
the same six steps on every case, no process lineage, verdicts read off the detector's
own sentences (``reports/local/dev/D1_AUDIT.md``). D1 is now its own loop,
:mod:`ath.agent.investigator` -- observations, competing explanations, one evidence gap,
at most one probe per round, update -- run by :func:`run_local_arm`, which mirrors the
frozen :func:`~ath.evaluation.ablation.arms.run_arm` step for step (manifest check,
footing, token accounting, scoring, row shape) and differs only in what investigates.
The arm keeps arm B's budgets: ``max_steps`` 8 and a 40-call tool cap.

The row store
--------------
M19 and M19b wrote one file per arm at the end of a run. A crash at case 19 of 20 lost
the night, and a rerun had no way to know what it had already done. Here a row is one
file, named by a key that says everything the V1 plan requires a result to be keyed on --
case, arm, provider, model, quantisation, repeat and seed -- and a run skips any key whose
file already parses. A degraded row is *written*, not rerun: silently retrying a failure
is how a model's reliability disappears from the results. Paths under ``reports/m19/`` or
``reports/m19b/`` are refused, by path, before any write.

The RAM guard
--------------
On the target laptop a 9B fits only when nearly everything else is closed. Below that
line the OS pages, and a 90-second call becomes a 15-minute one with no error anywhere.
So a row is refused before it starts when available memory is below a floor named for the
model's size class, and the available figure is recorded on the row that did start.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from ath.agent.claims import ClaimVerifier
from ath.agent.investigator import (
    D1_PROMPT_VERSION,
    INVESTIGATOR_MAX_TOKENS,
    MAX_PROBES,
    RESPONSE_SCHEMA,
    build_investigator,
)
from ath.agent.investigator import prompt_hashes as investigator_prompt_hashes
from ath.agent.llm import LLMClient
from ath.agent.ollama_llm import D1_SAMPLING, OllamaLLM, Sampling
from ath.agent.orchestrator import InvestigationConfig
from ath.agent.tools import ToolBox
from ath.correlation.chain import InvestigationCase
from ath.evaluation.ablation.arms import (
    STEP_BUDGET,
    TOOL_CALL_CAP,
    ArmConfig,
    ArmUnavailable,
    CaseResult,
    UnequalFooting,
    _check_inputs,
    attach_request_observer,
    begin_token_accounting,
    budgets_of,
    build_client,
    case_footing,
    detach_request_observer,
    request_records,
    tokens_spent,
)
from ath.evaluation.ablation.environment import (
    capture_environment,
    prompt_hashes,
    scoring_hashes,
)
from ath.evaluation.ablation.manifest import CaseManifest, telemetry_hash
from ath.evaluation.ablation.scoring import (
    UnknownRubric,
    capture_label_scores,
    context_size,
    cross_domain_evidence_recovery,
    domain_of_telemetry,
    footing_differences,
    score_case,
)
from ath.hunting.finding import Finding
from ath.telemetry.loader import Telemetry

# --------------------------------------------------------------------------------------
# The arm
# --------------------------------------------------------------------------------------

ARM_D1 = "D1_local_single"
"""One bounded local investigator, single pass, greedy and seeded (V1 rung 1)."""

LOCAL_TOOL_OUTPUT_BUDGET = 4096
"""Bytes of evidence ids one claim may contribute to the synthesis prompt.

The M19b value (``scripts/m19b_ablation.py: TOOL_OUTPUT_BUDGET``, ``PREREGISTERED.md``
section 1), restated here because ``src`` must not import a script. A test asserts the
two are equal so they cannot drift apart.
"""


D1_DESIGN_NOTE = (
    "one bounded investigator (ath.agent.investigator): observations -> <= 3 competing "
    "explanations -> one evidence gap -> at most one probe per round from a menu built "
    f"from the case's own evidence -> update; <= {MAX_PROBES} probe round(s), "
    f"<= {MAX_PROBES + 1} model calls, {INVESTIGATOR_MAX_TOKENS} output tokens per call, "
    "JSON-schema-bounded output. Budgets are arm B's (max_steps, tool cap)."
)


def ollama_factory(
    sampling: Sampling = D1_SAMPLING, **client_kwargs: Any,
) -> Callable[..., LLMClient]:
    """A factory :func:`~ath.evaluation.ablation.arms.build_client` will hand the arm's
    pinned model tag to. Sampling and every other client setting are fixed at factory
    construction, so the arm definition -- not an environment variable -- says what ran.
    """

    def factory(model: str) -> LLMClient:
        return OllamaLLM(model, sampling=sampling, **client_kwargs)

    return factory


def arm_d1(
    model: str,
    *,
    llm_factory: Callable[..., LLMClient] | None = None,
    sampling: Sampling = D1_SAMPLING,
    **client_kwargs: Any,
) -> ArmConfig:
    """The D1 arm: the bounded investigator on a local model, under arm B's budgets.

    ``client_kwargs`` (``base_url``, ``think``, ...) reach the local client through the
    default factory, so the freeze and the run build the client the same way. The
    client's output ``format`` is the investigator's JSON schema.
    """
    if not model:
        raise ValueError("arm D1 needs a local model tag, e.g. 'qwen3.5:4b'")
    factory = llm_factory or ollama_factory(sampling, format=RESPONSE_SCHEMA, **client_kwargs)
    return ArmConfig(
        name=ARM_D1,
        llm_factory=factory,
        config=InvestigationConfig(
            max_steps=STEP_BUDGET, use_llm_planner=True, use_llm_synthesis=True,
            tool_output_budget=LOCAL_TOOL_OUTPUT_BUDGET,
        ),
        requires_model=True,
        tool_call_cap=TOOL_CALL_CAP,
        generalist=False,
        model=model,
        design_note=D1_DESIGN_NOTE,
    )


LOCAL_ARM_BUILDERS: dict[str, Callable[..., ArmConfig]] = {ARM_D1: arm_d1}
"""The local arms, by name. Deliberately separate from ``arms.ARM_BUILDERS``."""


def investigator_environment() -> dict[str, Any]:
    """What the D1 loop reads and how it is bounded, for the freeze and its gate."""
    return {
        **investigator_prompt_hashes(),
        "max_probes": MAX_PROBES,
        "max_tokens": INVESTIGATOR_MAX_TOKENS,
    }


# --------------------------------------------------------------------------------------
# Running the arm
# --------------------------------------------------------------------------------------


def link_recovery(
    state: Any,
    links: Sequence[dict[str, Any]],
    domain_of: Any,
    *,
    manifest_digest: str,
    telemetry_digest: str,
) -> dict[str, Any]:
    """LINK-1 / LINK-2 style scores for one row, from its own state.

    ``links`` are the manifest's entries (``link_id``, ``identity.event_id``,
    ``endpoint.event_id``). Scored through :func:`cross_domain_evidence_recovery`, the
    M19b definition: a link is recovered when one accepted FACT or INFERENCE cites both
    ids. The result names the manifest and telemetry it was scored against, so a summary
    can refuse to read it beside a different manifest.
    """
    pairs = [(str(l["identity"]["event_id"]), str(l["endpoint"]["event_id"])) for l in links]
    ids = {tuple(sorted(pair)): str(l["link_id"]) for pair, l in zip(pairs, links)}
    try:
        recovery = cross_domain_evidence_recovery(state, pairs, domain_of)
    except UnknownRubric as exc:
        return {"links_error": str(exc), "link_scoring": {
            "manifest_hash": manifest_digest, "telemetry_hash": telemetry_digest,
            "investigator_version": D1_PROMPT_VERSION,
        }}
    recovered = {ids[tuple(sorted(link["evidence_ids"]))] for link in recovery["recovered_links"]}
    return {
        "links": {link_id: (link_id in recovered) for link_id in ids.values()},
        "links_defined": recovery["defined"],
        "links_recovered": recovery["recovered"],
        "link_recovery": recovery["recovery"],
        "link_scoring": {
            "manifest_hash": manifest_digest, "telemetry_hash": telemetry_digest,
            "investigator_version": D1_PROMPT_VERSION,
        },
    }


def run_local_arm(
    arm: ArmConfig,
    manifest: Sequence[CaseManifest],
    telemetry: Telemetry,
    cases: Sequence[InvestigationCase],
    *,
    manifest_digest: str = "",
    findings: Sequence[Finding] | None = None,
    environment: Any = None,
    llm: LLMClient | None = None,
    scripted: bool = False,
    label_scorer: Callable[[Any], dict[str, Any]] | None = None,
    required_footing: dict[str, Any] | None = None,
    links: dict[str, Sequence[dict[str, Any]]] | None = None,
) -> list[CaseResult]:
    """Run the D1 investigator over the manifest entries of one corpus.

    The frozen :func:`~ath.evaluation.ablation.arms.run_arm`, step for step -- the
    refusals, the manifest check, the per-case toolbox, the footing assertion, the
    request observer, the token accounting, the scorer and the row shape are the same
    calls -- except that :class:`~ath.agent.investigator.D1Investigator` investigates
    instead of the orchestrator over a generalist crew. ``environment`` is accepted for
    signature parity and unused: the investigator has no should-run gates to inform.

    ``links``: the manifest's cross-domain links by case key, scored on the row's own
    state and written beside the label scores with the hashes they were scored under.
    """
    if not arm.implemented:
        raise NotImplementedError(f"{arm.name} is declared, not implemented. {arm.design_note}")
    client = llm if llm is not None else build_client(arm)
    if scripted and not client.available:
        raise ArmUnavailable(
            f"{arm.name} was asked for a scripted run but the client {client.name!r} "
            "reports available=False; a scripted run must be given a scripted client."
        )
    if arm.requires_model and not client.available and not scripted:
        raise ArmUnavailable(
            f"{arm.name} requires a configured model and none is available (client "
            f"{client.name!r} reports available=False). Refusing to run: a deterministic "
            "run relabelled as a model arm would be a false row, not a weak one."
        )

    entries = list(manifest)
    cases_by_id = {c.case_id: c for c in cases}
    digest = telemetry_hash(telemetry)
    _check_inputs(entries, digest, cases_by_id)
    all_findings = (
        list(findings) if findings is not None
        else list({f.finding_id: f for c in cases for f in c.findings}.values())
    )
    verifier = ClaimVerifier(telemetry)
    domain_of = domain_of_telemetry(telemetry) if links else None

    results: list[CaseResult] = []
    for entry in entries:
        case = cases_by_id[entry.case_id]
        tools = ToolBox(telemetry, all_findings, list(cases), tool_call_budget=arm.tool_call_cap)
        investigator = build_investigator(tools, verifier, client, max_steps=arm.config.max_steps)
        footing = case_footing(tools, arm, digest)
        if required_footing is not None:
            differences = footing_differences({"required": required_footing, arm.name: footing})
            if differences:
                raise UnequalFooting(
                    f"{entry.key}: {arm.name} would not be on equal footing with the rows "
                    f"it is compared to: {differences}. Refusing the row."
                )
        measurements: list[dict[str, Any]] = []
        observed = attach_request_observer(client, measurements)
        baseline = begin_token_accounting(client)
        started = time.perf_counter()
        try:
            state = investigator.investigate(case)
        finally:
            detach_request_observer(client)
        elapsed = time.perf_counter() - started
        if observed:
            state.llm_requests = request_records(measurements, client)
        tokens = tokens_spent(client, baseline)
        case_scores = score_case(
            state, case, verifier, eligible_never_ran=[], wall_seconds=elapsed, tokens=tokens,
        )
        result = CaseResult(
            arm=arm.name, corpus=entry.corpus, case_id=entry.case_id,
            manifest_hash=manifest_digest, telemetry_hash=digest,
            configuration=client.name if client.available else "deterministic",
            llm_degraded=bool(state.llm_degraded), llm_status=str(state.llm_status),
            state=state.to_dict(), scores=case_scores, wall_seconds=elapsed, tokens=tokens,
            labels=dict(entry.labels),
            label_scores=capture_label_scores(entry.labels, case_scores),
            budgets=budgets_of(tools, arm, state), footing=footing,
            context=context_size(state), scripted=scripted,
        )
        graded = label_scorer(state) if label_scorer is not None else {}
        if graded:
            result.label_scores = {
                **result.label_scores,
                "incident_id": graded.get("incident_id"), "arm": result.labelled_arm,
                "configuration": result.configuration, "llm_degraded": result.llm_degraded,
                **{k: v for k, v in graded.items() if k != "incident_id"},
            }
        case_links = list((links or {}).get(entry.key) or ())
        if case_links:
            result.label_scores = {
                **result.label_scores,
                **link_recovery(
                    state, case_links, domain_of,
                    manifest_digest=manifest_digest, telemetry_digest=digest,
                ),
            }
        results.append(result)
    return results


# --------------------------------------------------------------------------------------
# The model, as the header records it
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelSpec:
    """What produced a row: provider, tag, quantisation, size and the daemon's digest.

    Two rows with the same tag but different digests were produced by different weights
    (a re-pulled model), and the digest is the only field that can say so.
    """

    provider: str
    model: str
    quantization: str | None = None
    parameter_size: str | None = None
    digest: str | None = None

    @property
    def quant_label(self) -> str:
        return self.quantization or "unknown-quant"

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "quantization": self.quantization,
            "parameter_size": self.parameter_size,
            "digest": self.digest,
        }

    @classmethod
    def from_description(cls, described: dict[str, Any]) -> "ModelSpec":
        """From :meth:`ath.agent.ollama_llm.OllamaLLM.describe`."""
        return cls(
            provider=str(described.get("provider", "")),
            model=str(described.get("model", "")),
            quantization=described.get("quantization_level"),
            parameter_size=described.get("parameter_size"),
            digest=described.get("digest"),
        )


# --------------------------------------------------------------------------------------
# The row store
# --------------------------------------------------------------------------------------

FROZEN_REPORT_PREFIXES: tuple[str, ...] = ("reports/m19", "reports/m19b")
"""Directories this tier reads and never writes."""

MAX_ROW_BYTES = 50 * 1024 * 1024
"""The same bound ``scripts/m19_ablation.py`` puts on an artifact, for the same reason."""

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


class FrozenPathRefused(RuntimeError):
    """A write was aimed at a frozen experiment's directory."""


class RowTooLarge(RuntimeError):
    """A row would exceed :data:`MAX_ROW_BYTES`; refused, not truncated."""


def refuse_frozen_path(path: Path, root: Path) -> Path:
    """Refuse, by path, any write under a frozen experiment's reports directory."""
    resolved = Path(path).resolve()
    for prefix in FROZEN_REPORT_PREFIXES:
        frozen = (Path(root) / prefix).resolve()
        if resolved == frozen or frozen in resolved.parents:
            raise FrozenPathRefused(
                f"refusing to write {path}: {prefix}/ is a frozen experiment. The local "
                "tier reports under reports/local/ and never beside a frozen row."
            )
    return Path(path)


def _slug(value: Any) -> str:
    text = _UNSAFE.sub("_", str(value)).strip("_")
    return text or "_"


@dataclass(frozen=True)
class RowKey:
    """Everything a V1 result row is keyed on. See the module docstring."""

    corpus: str
    case_id: str
    arm: str
    provider: str
    model: str
    quantization: str
    repeat: int
    seed: int | None
    manifest_hash: str = ""
    """The manifest the row was run against. Part of the key since the first preview:
    the 2026-09-15 rows were keyed without it, so a rerun against the regenerated
    manifest would have found every key "complete" and written nothing. A row keyed on a
    different manifest is a different row."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus,
            "case_id": self.case_id,
            "arm": self.arm,
            "provider": self.provider,
            "model": self.model,
            "quantization": self.quantization,
            "repeat": self.repeat,
            "seed": self.seed,
            "manifest_hash": self.manifest_hash,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RowKey":
        return cls(
            corpus=str(payload["corpus"]),
            case_id=str(payload["case_id"]),
            arm=str(payload["arm"]),
            provider=str(payload["provider"]),
            model=str(payload["model"]),
            quantization=str(payload["quantization"]),
            repeat=int(payload["repeat"]),
            seed=None if payload.get("seed") is None else int(payload["seed"]),
            manifest_hash=str(payload.get("manifest_hash") or ""),
        )

    @property
    def digest(self) -> str:
        """Short hash of the exact key. The readable part of a filename is slugged and can
        collide (``a:b`` and ``a_b``); this part cannot, so the mapping stays injective."""
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]

    @property
    def filename(self) -> str:
        seed = "noseed" if self.seed is None else f"seed{self.seed}"
        manifest = f"m{self.manifest_hash[:12]}__" if self.manifest_hash else ""
        return (
            f"{_slug(self.corpus)}__{_slug(self.case_id)}__{_slug(self.arm)}__"
            f"{_slug(self.provider)}__{_slug(self.model)}__{_slug(self.quantization)}__"
            f"rep{self.repeat}__{seed}__{manifest}{self.digest}.json"
        )


def row_path(rows_dir: Path, key: RowKey) -> Path:
    return Path(rows_dir) / key.filename


def read_row(path: Path) -> dict[str, Any] | None:
    """The row payload, or ``None`` when the file is absent, unparseable or not a row.

    A half-written file from a crash mid-write is ``None`` and will be rewritten; a
    complete one -- degraded or not -- is a row and will not be run again.
    """
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    if not isinstance(payload.get("key"), dict) or not isinstance(payload.get("row"), dict):
        return None
    if "arm" not in payload["row"] or "scores" not in payload["row"]:
        return None
    return payload


def is_complete(path: Path) -> bool:
    return read_row(path) is not None


def write_row(
    rows_dir: Path,
    key: RowKey,
    result: CaseResult,
    header: dict[str, Any],
    *,
    root: Path,
) -> Path:
    """Write one row atomically (temp file, then replace) inside the guards.

    Atomic so that a crash never leaves a file that both exists and parses as half a row:
    the temp name is never a row path, and ``os.replace`` is all-or-nothing.
    """
    path = refuse_frozen_path(row_path(rows_dir, key), root)
    payload = {
        "key": key.to_dict(),
        "header": dict(header),
        "row": result.to_dict(),
    }
    text = json.dumps(payload, indent=2, default=str)
    size = len(text.encode("utf-8"))
    if size > MAX_ROW_BYTES:
        raise RowTooLarge(
            f"refusing to write {path}: {size / 1e6:.1f} MB exceeds {MAX_ROW_BYTES / 1e6:.0f} MB"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".partial")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)
    return path


def completed_rows(rows_dir: Path) -> list[dict[str, Any]]:
    """Every complete row under ``rows_dir``, sorted by filename."""
    directory = Path(rows_dir)
    if not directory.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        payload = read_row(path)
        if payload is not None:
            rows.append(payload)
    return rows


# --------------------------------------------------------------------------------------
# The RAM guard
# --------------------------------------------------------------------------------------

GIB = 1024 ** 3

RAM_FLOORS_BYTES: dict[str, int] = {
    "4B": int(4.5 * GIB),
    "9B": int(9.5 * GIB),
}
"""Available memory required before a row may start, by model size class.

The V1 plan's figures for this machine (16 GB, ~13 GB in use with normal apps): a 4B Q4
runs beside a browser, a 9B Q4 needs everything else closed. Named constants so the
amendment can cite them; a floor that is wrong is corrected here and nowhere else.

The floor is the system memory the weights take when they are loaded into it. A model
the daemon already holds -- in VRAM or in system memory -- has spent that memory, and
:func:`check_ram` credits every loaded byte against the floor. On a GPU host the guard is
therefore exact only once the model is resident; before the first load it compares the
host's free memory against a CPU-load floor the run may never need. Load the model
(``keep_alive`` set) before the first row, and the credit applies from the first row.
"""


def ram_floor_for(parameter_size: str | None) -> int | None:
    """The floor for a model whose daemon-reported size is e.g. ``"4.7B"`` or ``"9.1B"``.

    ``None`` when the size is unknown or outside both classes: an unguarded run is then a
    *recorded* choice (the row says the floor was ``None``) rather than a silent one.
    """
    if not parameter_size:
        return None
    match = re.match(r"\s*([0-9]+(?:\.[0-9]+)?)\s*B", str(parameter_size), re.IGNORECASE)
    if not match:
        return None
    billions = float(match.group(1))
    if billions <= 6.0:
        return RAM_FLOORS_BYTES["4B"]
    if billions <= 12.0:
        return RAM_FLOORS_BYTES["9B"]
    return None


def available_ram_bytes() -> int | None:
    """Physical memory currently available, or ``None`` when the platform cannot say."""
    if sys.platform == "win32":
        return _windows_available_bytes()
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _windows_available_bytes() -> int | None:
    class _MemoryStatusEx(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    try:
        status = _MemoryStatusEx()
        status.dwLength = ctypes.sizeof(_MemoryStatusEx)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
            return None
        return int(status.ullAvailPhys)
    except Exception:  # noqa: BLE001 -- a guard that cannot read is a guard that says None
        return None


@dataclass(frozen=True)
class RamVerdict:
    """Whether a row may start. ``ok`` is ``None`` when nothing could be measured."""

    ok: bool | None
    available_bytes: int | None
    floor_bytes: int | None
    message: str
    resident_bytes: int = 0
    """System memory the model already occupies in the daemon (kept alive from an earlier
    call). Credited against the floor: those bytes are spent, not needed again."""

    @property
    def effective_bytes(self) -> int | None:
        if self.available_bytes is None:
            return None
        return self.available_bytes + self.resident_bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "available_bytes": self.available_bytes,
            "resident_bytes": self.resident_bytes,
            "effective_bytes": self.effective_bytes,
            "floor_bytes": self.floor_bytes,
            "message": self.message,
        }


def check_ram(
    floor_bytes: int | None, available_bytes: int | None, resident_bytes: int = 0,
) -> RamVerdict:
    """The guard. ``resident_bytes`` is what the model already holds, so a daemon that kept
    the weights loaded is not refused for the memory the weights are using."""
    resident = max(0, int(resident_bytes or 0))
    if floor_bytes is None:
        return RamVerdict(
            None, available_bytes, None,
            "no RAM floor for this model size; the row is unguarded and says so", resident,
        )
    if available_bytes is None:
        return RamVerdict(
            None, None, floor_bytes,
            "available RAM could not be measured on this platform; proceeding unguarded",
            resident,
        )
    effective = available_bytes + resident
    credit = f" plus {resident / GIB:.2f} GiB already resident" if resident else ""
    if effective < floor_bytes:
        return RamVerdict(
            False, available_bytes, floor_bytes,
            f"refusing to start: {available_bytes / GIB:.2f} GiB available{credit} is below "
            f"the {floor_bytes / GIB:.1f} GiB floor for this model; below it the OS pages and "
            "a 90 s call becomes a 15 min one with no error. Close applications and retry.",
            resident,
        )
    return RamVerdict(
        True, available_bytes, floor_bytes,
        f"{available_bytes / GIB:.2f} GiB available{credit}, floor {floor_bytes / GIB:.1f} GiB",
        resident,
    )


# --------------------------------------------------------------------------------------
# The local freeze
# --------------------------------------------------------------------------------------

LOCAL_GATED_FIELDS: tuple[str, ...] = (
    "prompts", "scoring", "manifest_hash", "model_digest", "daemon_version",
    "client_configuration", "investigator",
)
"""What must match between the local freeze and a scored local run.

Not the commit: the dev loop commits between passes by design, and the prompt and scoring
hashes are what a commit could change that matters. Not RAM: recorded, because it explains
a slow row, and never gated, because it changes by the minute.
"""

_CONFIGURATION_UNGATED: frozenset[str] = frozenset({
    "base_url", "timeout_seconds_per_attempt", "max_attempts", "backoff_seconds",
})
"""Client settings that change where and how patiently a call is made, not what it
computes. Recorded, not gated."""


def _ollama_environment_variables() -> dict[str, str]:
    return {k: v for k, v in sorted(os.environ.items()) if k.startswith("OLLAMA_")}


def gpu_summary() -> list[dict[str, Any]] | None:
    """The GPUs ``nvidia-smi`` reports, or ``None`` when there is no such tool.

    Recorded, never gated: a row produced with the weights in VRAM and one produced on
    the CPU are the same experiment at very different speeds, and a reader comparing
    wall times needs to know which was which. The residency of the model itself is on
    each row (``model_residency``); this is the machine.
    """
    import shutil  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    if shutil.which("nvidia-smi") is None:
        return None
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total,memory.used,driver_version",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=15, check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    gpus: list[dict[str, Any]] = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 4:
            continue
        try:
            gpus.append({
                "name": parts[0], "memory_total_mib": int(float(parts[1])),
                "memory_used_mib": int(float(parts[2])), "driver_version": parts[3],
            })
        except ValueError:
            continue
    return gpus


def local_environment(
    root: Path,
    *,
    manifest_hash: str,
    arm: ArmConfig,
    described: dict[str, Any],
    manifest_head: str = "",
    available_ram: int | None = None,
) -> dict[str, Any]:
    """The frozen environment for a local run.

    Wraps :func:`~ath.evaluation.ablation.environment.capture_environment` -- so the git
    state, prompt hashes, scoring hashes, tool surface and the *hosted* request
    configuration are recorded exactly as M19b recorded them, which is what lets a reader
    see they did not move -- and adds the local section: what the daemon said about
    itself and the model, and what the client will send.
    """
    base = capture_environment(
        root, manifest_hash=manifest_hash, manifest_head=manifest_head,
        arm_configs=[arm], credential_present=False,
    )
    base["local"] = {
        "daemon": {
            "provider": described.get("provider"),
            "base_url": described.get("base_url"),
            "version": described.get("daemon_version"),
            "environment_variables": _ollama_environment_variables(),
        },
        "model": ModelSpec.from_description(described).to_dict(),
        "model_details": {
            "family": described.get("family"),
            "format": described.get("format"),
            "size_bytes": described.get("size_bytes"),
            "modified_at": described.get("modified_at"),
            "capabilities": list(described.get("capabilities") or []),
            "model_context_length": described.get("model_context_length"),
        },
        "client_configuration": dict(described.get("configuration") or {}),
        "investigator": investigator_environment(),
        "machine": {
            "platform": platform.platform(),
            "processor": platform.processor(),
            "available_ram_bytes": available_ram,
            "gpus": gpu_summary(),
            "note": "available RAM and GPUs are recorded, never gated",
        },
    }
    return base


def _gated_configuration(configuration: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in configuration.items() if k not in _CONFIGURATION_UNGATED}


def check_local_environment(
    recorded: dict[str, Any],
    *,
    manifest_hash: str,
    described: dict[str, Any],
) -> list[str]:
    """Differences between the freeze and the live world that make a run not-the-frozen-
    experiment. Empty when clean. Descriptions, so a refusal names what moved."""
    differences: list[str] = []

    for name, live in prompt_hashes().items():
        frozen = (recorded.get("prompts") or {}).get(name)
        if frozen != live:
            differences.append(f"prompts.{name}: frozen {str(frozen)[:12]} live {live[:12]}")
    for name, live in scoring_hashes().items():
        frozen = (recorded.get("scoring") or {}).get(name)
        if frozen != live:
            differences.append(f"scoring.{name}: frozen {str(frozen)[:12]} live {live[:12]}")

    frozen_manifest = recorded.get("manifest_hash")
    if frozen_manifest != manifest_hash:
        differences.append(
            f"manifest_hash: frozen {str(frozen_manifest)[:12]} live {manifest_hash[:12]}"
        )

    local = recorded.get("local") or {}
    frozen_model = local.get("model") or {}
    live_model = ModelSpec.from_description(described)
    if frozen_model.get("digest") != live_model.digest:
        differences.append(
            f"model_digest: frozen {str(frozen_model.get('digest'))[:12]} live "
            f"{str(live_model.digest)[:12]} (the weights changed; re-freeze and say so)"
        )
    if frozen_model.get("model") != live_model.model:
        differences.append(
            f"model: frozen {frozen_model.get('model')!r} live {live_model.model!r}"
        )
    frozen_version = (local.get("daemon") or {}).get("version")
    if frozen_version != described.get("daemon_version"):
        differences.append(
            f"daemon_version: frozen {frozen_version!r} live {described.get('daemon_version')!r}"
        )
    frozen_configuration = _gated_configuration(local.get("client_configuration") or {})
    live_configuration = _gated_configuration(dict(described.get("configuration") or {}))
    for name in sorted(set(frozen_configuration) | set(live_configuration)):
        if frozen_configuration.get(name) != live_configuration.get(name):
            differences.append(
                f"client_configuration.{name}: frozen {frozen_configuration.get(name)!r} "
                f"live {live_configuration.get(name)!r}"
            )
    frozen_investigator = dict(local.get("investigator") or {})
    live_investigator = investigator_environment()
    for name in sorted(set(frozen_investigator) | set(live_investigator)):
        if frozen_investigator.get(name) != live_investigator.get(name):
            differences.append(
                f"investigator.{name}: frozen {str(frozen_investigator.get(name))[:12]} "
                f"live {str(live_investigator.get(name))[:12]}"
            )
    return differences
