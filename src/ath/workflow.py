"""Checkpointed investigation workflow: telemetry -> seed -> investigation -> verdict -> report.

This is the operational path for one case, or a batch of cases, on telemetry ATH did not
generate. It composes code that already exists and is already tested elsewhere; it does
not re-derive any of it:

* telemetry: :func:`ath.evaluation.real_cases.load_source`, ``slice_telemetry`` and
  ``_write_slice`` (the slice is written as canonical CSV and **reloaded**, so every
  later stage sees exactly what is on disk);
* seed: :func:`~ath.evaluation.real_cases.analyst_incident` (one analyst-selected
  record) or :func:`~ath.evaluation.real_cases.select_incident` / ATH detection and
  correlation (detection mode);
* investigation and verdict: :func:`ath.evaluation.real_cases.prepare` re-derives the
  incident from the sealed slice, and :func:`ath.evaluation.auth_execution.evaluate_case`
  runs :func:`~ath.agent.operational.investigate_operational` and applies the
  evaluator's decision rule (triage of the seed for the deterministic engine, the
  model's disposition for D1, abstain whenever execution is incomplete);
* report: :func:`ath.reporting.build_report` (called by ``evaluate_case`` with the
  triage disposition and model name), rendered to Markdown, HTML and JSON.

It is **not** an evaluator. A batch spec's ``expected_decision`` is shown beside the
verdict for scoring only, after the investigation; ``useful_refs`` and ``link`` are not
scored here (use :mod:`ath.evaluation.real_cases` for those metrics) and ``run.json``
says so.

Run directory (one per case)::

    run.json                  written last: inputs, profile, model, load_seconds,
                              one sha256 per stage, verdict. Its presence means done.
    01-telemetry/             slice/*.csv (canonical) + telemetry.json (digest)
    02-seed/seed.json         the seed finding and case ids, or the detection findings
    03-investigation/state.json   state.to_dict(), the operational audit, verdict inputs
    04-report/report.{md,html,json}
    attempts/attempt-N.json   a RAM-guard block, never overwritten (not a stage)

Sealing and resume
------------------
Each stage is built in ``<stage>.partial/``, sealed by ``STAGE.json`` (sha256 of every
artifact file, the stage's input hash, and a hash of the seal itself; JSON artifacts go
through :func:`~ath.evaluation.auth_execution.write_new`), and then renamed into place in
one ``os.replace``. A stage directory therefore exists only once complete; a leftover
``.partial`` directory is a killed attempt, never a stage, and is discarded.

A stage's input hash chains the previous stage's seal with that stage's own parameters;
stage 01's parameters include the telemetry path, kind, window, devices, seed refs, a
fingerprint of the source (names, sizes and modification times -- not a content hash of
what may be a multi-gigabyte export) and the hash of ATH's source code. On resume:

* a stage that exists and validates against the expected input hash is **reused**;
* a stage whose artifacts or seal were altered, or whose inputs differ from this
  invocation, is **refused** (:class:`WorkflowRefused`) -- never recomputed or
  overwritten. Choose a new run directory;
* a missing stage is computed.

The investigation cannot be reloaded as live objects from ``state.json``, and the
report needs them. So stages 03 and 04 are computed in **one step** from the same live
state and sealed back to back; a case is only left with 03 and no 04 if the process died
between the two renames (or someone deleted 04). Then:

* **deterministic engine**: the investigation is re-run and must reproduce the sealed
  ``state.json`` exactly, apart from its run id, timestamps and elapsed time
  (:data:`VOLATILE_KEYS`). Only then is 04 built, from the re-run, and its seal says so
  (``rebuilt_from_rerun``). A mismatch is refused.
* **d1**: a model investigation is not reproducible, so a report rebuilt from a fresh run
  would describe a different investigation than the sealed one. Refused; use a new run
  directory.

Model loading
-------------
The engine's model sits behind :class:`ModelSession`: one client per batch, loaded at
most once (lazily, by the first case that needs an investigation), with a RAM-guard
check before every case. :class:`OllamaSession` sends one warm-up request with an empty
prompt and ``keep_alive: -1`` (as the Colab notebook does), checks residency once, and
records ``load_seconds``. :class:`ScriptedSession` wraps a
:class:`~ath.agent.llm.ScriptedLLM` for tests, labelled scripted everywhere. A blocked
case is recorded (``attempts/`` and ``INDEX.json``), never skipped silently.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ath.agent.llm import ScriptedLLM
from ath.correlation import correlate
from ath.evaluation import auth_execution as pilot
from ath.evaluation import real_cases as real
from ath.evaluation.ablation.local import available_ram_bytes, check_ram, ram_floor_for
from ath.evaluation.ablation.manifest import telemetry_digest
from ath.evaluation.external_labels import resolve_refs
from ath.experiments.identity import sha256_json
from ath.hunting import run_hunt
from ath.reporting import IndexEntry, render_index, render_markdown
from ath.reporting.html import render_html
from ath.telemetry.loader import Telemetry, load_telemetry

VERSION = "ath-workflow-v1"
STAGE_TELEMETRY, STAGE_SEED, STAGE_INVESTIGATION, STAGE_REPORT = (
    "01-telemetry", "02-seed", "03-investigation", "04-report")
STAGES = (STAGE_TELEMETRY, STAGE_SEED, STAGE_INVESTIGATION, STAGE_REPORT)
SEAL = "STAGE.json"
RUN = "run.json"
INDEX = "INDEX.json"
ATTEMPTS = "attempts"
ENGINES = ("deterministic", "d1")
PROFILES = ("operational-v2", "operational-v3", "operational-v4", "operational-v5", "operational-v6",
            "operational-v7")
COMPLETE, BLOCKED = "complete", "blocked"
VOLATILE_KEYS = frozenset({"run_id", "started_at", "called_at", "elapsed_seconds"})
"""State fields that legitimately differ between two runs of the same deterministic
investigation; everything else must match for a report to be rebuilt from a re-run."""
WARMUP_TIMEOUT_SECONDS = 600


class WorkflowRefused(ValueError):
    """A run directory that cannot be resumed as asked. Choose a new run directory."""


class ModelNotResident(RuntimeError):
    """The warm-up answered but the daemon does not hold the model."""


# -- inputs -----------------------------------------------------------------------------


@dataclass(frozen=True)
class CaseInputs:
    """What one case investigates. Labels are carried for scoring only, never hashed
    into a stage and never passed to the investigation."""

    key: str
    telemetry: str
    kind: str
    seed_mode: str
    anchor_refs: tuple[str, ...] = ()
    window: dict | None = None
    devices: tuple[str, ...] | None = None
    cluster: str = "default"
    expected_decision: str | None = None
    labels: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in real.SOURCE_KINDS:
            raise ValueError(f"kind must be one of {real.SOURCE_KINDS}")
        if self.seed_mode not in real.SEED_MODES:
            raise ValueError(f"seed_mode must be one of {real.SEED_MODES}")
        if self.seed_mode == real.ANALYST and len(self.anchor_refs) != 1:
            raise ValueError(f"an analyst seed is exactly one initial record ({real.SEED_POLICY}); "
                             f"got {len(self.anchor_refs)} refs")
        if self.window is not None and (real._stamp(self.window.get("start")) is None
                                        or real._stamp(self.window.get("end")) is None):
            raise ValueError("window needs ISO start and end with a timezone")

    @classmethod
    def from_spec(cls, spec_case: dict, spec_dir: Path, seed_mode: str) -> CaseInputs:
        source = spec_case["source"]
        return cls(
            key=spec_case["key"], telemetry=str((spec_dir / source["path"]).resolve()),
            kind=source["kind"], seed_mode=seed_mode, anchor_refs=tuple(spec_case["anchor_refs"]),
            window=spec_case.get("window"),
            devices=tuple(spec_case["devices"]) if spec_case.get("devices") else None,
            cluster=source.get("cluster", "default"),
            expected_decision=spec_case.get("expected_decision"),
            labels={"expected_decision": spec_case.get("expected_decision"),
                    "provenance": spec_case.get("provenance"), "label_source": spec_case.get("label_source"),
                    **pilot.case_metadata(spec_case),
                    "not_scored": [k for k in ("useful_refs", "link") if spec_case.get(k)]},
        )

    def investigation_inputs(self) -> dict:
        """Everything that decides what is investigated; hashed into stage 01."""
        return {"telemetry": self.telemetry, "kind": self.kind, "cluster": self.cluster,
                "window": self.window, "devices": list(self.devices) if self.devices else None,
                "seed_mode": self.seed_mode, "anchor_refs": list(self.anchor_refs)}

    def to_dict(self) -> dict:
        return {"key": self.key, **self.investigation_inputs(), "labels": self.labels}


def source_fingerprint(path: Path) -> list:
    """Names, sizes and modification times under ``path`` -- cheap, not a content hash."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"telemetry source not found: {path}")
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
    return [[p.relative_to(path).as_posix() if p != path else p.name, p.stat().st_size, p.stat().st_mtime_ns]
            for p in files]


# -- model sessions ---------------------------------------------------------------------


class ModelSession:
    """One model client per batch, loaded at most once, guarded before every case.

    Subclasses provide :meth:`_identity`, :meth:`_load` and :meth:`guard`. ``loads``
    counts warm-ups, so a batch can show it loaded the model once for N cases.
    """

    scripted = False

    def __init__(self, client: Any) -> None:
        self.client = client
        self.loads = 0
        self.load_record: dict | None = None
        self._identity_cache: dict | None = None

    def identity(self) -> dict:
        """The model's identity, hashed into the investigation stage's inputs."""
        if self._identity_cache is None:
            self._identity_cache = self._identity()
        return self._identity_cache

    def ensure_loaded(self) -> dict:
        if self.load_record is None:
            self.load_record = self._load()
            self.loads += 1
        return self.load_record

    def blocks(self, guard: dict) -> bool:
        """A live model is blocked unless the guard says ok (undecidable blocks, as in
        :func:`ath.evaluation.auth_execution.run_rows`)."""
        return guard.get("ok") is not True

    def _identity(self) -> dict:
        raise NotImplementedError

    def _load(self) -> dict:
        raise NotImplementedError

    def guard(self) -> dict:
        raise NotImplementedError


class OllamaSession(ModelSession):
    """A local Ollama model: ``describe()`` once, one warm-up request, residency once."""

    def __init__(self, model: str, profile, client: Any = None,
                 opener: Callable[..., Any] = urllib.request.urlopen) -> None:
        super().__init__(client if client is not None else pilot._client(model, profile))
        self._open = opener

    def _identity(self) -> dict:
        description = self.client.describe()
        return {"provider": description.get("provider"), "model": description.get("model"),
                "digest": description.get("digest"), "daemon_version": description.get("daemon_version"),
                "parameter_size": description.get("parameter_size"),
                "quantization_level": description.get("quantization_level"),
                "configuration": self.client.configuration(), "scripted": False}

    def warmup_body(self) -> dict:
        """Empty prompt: the daemon loads the weights and answers without generating."""
        return {"model": self.client.model, "stream": False, "keep_alive": -1,
                "options": {"num_ctx": self.client.num_ctx}}

    def _load(self) -> dict:
        self.identity()
        request = urllib.request.Request(
            self.client.base_url + "/api/generate", data=json.dumps(self.warmup_body()).encode("utf-8"),
            headers={"Content-Type": "application/json"})
        started = time.perf_counter()
        with self._open(request, timeout=WARMUP_TIMEOUT_SECONDS) as response:
            answer = json.load(response)
        load_seconds = time.perf_counter() - started
        if isinstance(answer, dict) and answer.get("error"):
            raise ModelNotResident(f"warm-up failed for {self.client.model!r}: {answer['error']}")
        residency = self.client.residency()
        if not residency.get("size"):
            raise ModelNotResident(f"{self.client.model!r} is not resident after the warm-up request; "
                                   "the daemon did not keep it loaded (check keep_alive and memory)")
        return {"warmup_requests": 1, "task_prompt_sent": False, "keep_alive": -1,
                "load_seconds": load_seconds, "residency": residency}

    def guard(self) -> dict:
        floor = ram_floor_for(self.identity().get("parameter_size"))
        return check_ram(floor, available_ram_bytes(), self.client.resident_bytes()).to_dict()


class ScriptedSession(ModelSession):
    """A :class:`ScriptedLLM` behind the same interface; for tests, labelled scripted.

    No weights are loaded, so the default guard answers ``ok: None`` with that reason and
    does not block; a test injects ``guard`` to stage a block.
    """

    scripted = True

    def __init__(self, client: ScriptedLLM, guard: Callable[[], dict] | None = None) -> None:
        if not isinstance(client, ScriptedLLM):
            raise TypeError("ScriptedSession takes a ScriptedLLM")
        super().__init__(client)
        self._guard = guard

    def _identity(self) -> dict:
        return {"provider": "scripted", "model": self.client.name, "scripted": True}

    def _load(self) -> dict:
        return {"warmup_requests": 1, "task_prompt_sent": False, "load_seconds": 0.0,
                "residency": None, "note": "scripted client: nothing to load"}

    def guard(self) -> dict:
        if self._guard is not None:
            return self._guard()
        return {"ok": None, "message": "scripted client loads no weights; the RAM guard does not apply"}

    def blocks(self, guard: dict) -> bool:
        return guard.get("ok") is False


# -- stage mechanics --------------------------------------------------------------------


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _hash_tree(directory: Path) -> dict:
    return {p.relative_to(directory).as_posix(): _file_sha256(p)
            for p in sorted(directory.rglob("*")) if p.is_file() and p.name != SEAL}


def read_stage(run_dir: Path, name: str) -> dict | None:
    """A stage's validated seal, or ``None`` when the stage does not exist.

    Refuses a seal whose own hash, or any artifact's hash, no longer matches: an altered
    stage is never trusted and never recomputed over.
    """
    directory = Path(run_dir) / name
    if not directory.exists():
        return None
    try:
        seal = json.loads((directory / SEAL).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise WorkflowRefused(f"{name}: the stage seal is missing or unreadable ({error}); "
                              "the run directory was altered. Choose a new run directory.") from error
    body = {k: v for k, v in seal.items() if k != "stage_sha256"}
    if seal.get("workflow") != VERSION or seal.get("stage") != name or sha256_json(body) != seal.get("stage_sha256"):
        raise WorkflowRefused(f"{name}: the stage seal was altered. Choose a new run directory.")
    if _hash_tree(directory) != seal["artifacts"]:
        raise WorkflowRefused(f"{name}: stage artifacts differ from their seal (tampered or edited). "
                              "Choose a new run directory.")
    return seal


def _open_stage(run_dir: Path, name: str, params: dict) -> dict | None:
    seal = read_stage(run_dir, name)
    if seal is not None and seal["input_sha256"] != sha256_json(params):
        raise WorkflowRefused(
            f"{name}: this run directory was sealed for different inputs (telemetry, seed, engine, "
            "profile, model or ATH source changed). A sealed stage is never recomputed or "
            "overwritten; choose a new run directory.")
    return seal


def _write_stage(run_dir: Path, name: str, params: dict, build: Callable[[Path], dict]) -> dict:
    """Build a stage in ``<name>.partial``, seal it, and rename it into place."""
    final = Path(run_dir) / name
    if final.exists():
        raise FileExistsError(final)
    partial = Path(run_dir) / f"{name}.partial"
    if partial.exists():
        shutil.rmtree(partial)  # a killed attempt, never a stage
    partial.mkdir(parents=True)
    summary = build(partial)
    body = {"workflow": VERSION, "stage": name, "input_sha256": sha256_json(params), "inputs": params,
            "artifacts": _hash_tree(partial), "summary": summary,
            "sealed_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    pilot.write_new(partial / SEAL, {**body, "stage_sha256": sha256_json(body)})
    os.replace(partial, final)
    return read_stage(run_dir, name)


def _write_text(path: Path, text: str) -> None:
    # Only ever inside a fresh .partial stage directory; "x" still refuses a replace.
    with path.open("x", encoding="utf-8") as handle:
        handle.write(text)


def _read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def strip_volatile(value: Any) -> Any:
    """``value`` without :data:`VOLATILE_KEYS`, at any depth."""
    if isinstance(value, dict):
        return {k: strip_volatile(v) for k, v in value.items() if k not in VOLATILE_KEYS}
    if isinstance(value, list):
        return [strip_volatile(v) for v in value]
    return value


# -- the run ----------------------------------------------------------------------------


@dataclass
class Workflow:
    """Engine, profile and model shared by every case of one invocation."""

    engine: str
    profile_version: str = "operational-v5"
    session: ModelSession | None = None
    source_sha256: str = field(default_factory=pilot.source_hash)
    _sources: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.engine not in ENGINES:
            raise ValueError(f"engine must be one of {ENGINES}")
        if (self.engine == "d1") != (self.session is not None):
            raise ValueError("d1 needs a model session; the deterministic engine takes none")
        self.profile = pilot.profile_for(self.profile_version)

    def model_identity(self) -> dict | None:
        return self.session.identity() if self.session is not None else None

    def load_source(self, inputs: CaseInputs) -> tuple[Telemetry, dict]:
        """One load per source per invocation, shared by every case cut from it."""
        key = (inputs.kind, inputs.telemetry, inputs.cluster)
        if key not in self._sources:
            self._sources[key] = real.load_source(inputs.kind, Path(inputs.telemetry), inputs.cluster)
        return self._sources[key]

    # -- stages ---------------------------------------------------------------------

    def _telemetry(self, run_dir: Path, inputs: CaseInputs, ran: list) -> tuple[dict, Telemetry]:
        params = {"workflow": VERSION, "inputs": inputs.investigation_inputs(),
                  "source_fingerprint": source_fingerprint(Path(inputs.telemetry)),
                  "source_sha256": self.source_sha256}
        seal = _open_stage(run_dir, STAGE_TELEMETRY, params)
        if seal is None:
            def build(directory):
                full, ingestion = self.load_source(inputs)
                cut = real.slice_telemetry(full, inputs.window, list(inputs.devices) if inputs.devices else None)
                telemetry = real._write_slice(cut, directory / "slice")
                summary = {"ingestion": ingestion, "window": inputs.window,
                           "devices": list(inputs.devices) if inputs.devices else None,
                           "events": int(telemetry.event_count), "telemetry_sha256": telemetry_digest(telemetry, 2)}
                pilot.write_new(directory / "telemetry.json", summary)
                return {"events": summary["events"], "telemetry_sha256": summary["telemetry_sha256"]}
            seal = _write_stage(run_dir, STAGE_TELEMETRY, params, build)
            ran.append(STAGE_TELEMETRY)
        telemetry = load_telemetry(Path(run_dir) / STAGE_TELEMETRY / "slice")
        if telemetry_digest(telemetry, 2) != seal["summary"]["telemetry_sha256"]:
            raise WorkflowRefused(f"{STAGE_TELEMETRY}: the reloaded slice differs from its sealed digest")
        return seal, telemetry

    def _seed(self, run_dir: Path, inputs: CaseInputs, telemetry: Telemetry, previous: dict,
              ran: list) -> tuple[dict, dict]:
        params = {"previous": previous["stage_sha256"], "seed_mode": inputs.seed_mode,
                  "seed_policy": real.SEED_POLICY if inputs.seed_mode == real.ANALYST else None}
        seal = _open_stage(run_dir, STAGE_SEED, params)
        if seal is None:
            def build(directory):
                seed = seed_case(telemetry, inputs)
                pilot.write_new(directory / "seed.json", seed)
                return {"status": seed["status"], "case_ids": seed["case_ids"]}
            seal = _write_stage(run_dir, STAGE_SEED, params, build)
            ran.append(STAGE_SEED)
        return seal, _read_json(Path(run_dir) / STAGE_SEED / "seed.json")

    def _investigate(self, inputs: CaseInputs, telemetry: Telemetry, seed: dict):
        case = real.RealCase(inputs.key, telemetry, inputs.expected_decision or "", (), None,
                             tuple(seed["case_ids"]), inputs.seed_mode, tuple(seed["anchor_ids"]))
        prepared = real.prepare(case)  # re-derives the sealed incident, or refuses
        client = self.session.client if self.session is not None else None
        row, report = pilot.evaluate_case(case, self.engine, client, scripted=bool(self.session and self.session.scripted),
                                          profile=self.profile, prepared=prepared)
        _, incident, environment = prepared
        triage = pilot.deterministic_disposition(incident, environment) if self.engine == "deterministic" else None
        return row, report, triage

    def _write_report(self, run_dir: Path, previous: dict, report, rebuilt: dict | None, ran: list) -> dict:
        params = {"previous": previous["stage_sha256"]}

        def build(directory):
            _write_text(directory / "report.md", render_markdown(report))
            _write_text(directory / "report.html", render_html(report))
            pilot.write_new(directory / "report.json", report.to_dict())
            verdict = report.verdict
            return {"verdict": verdict.disposition if verdict else "Incomplete",
                    "complete": verdict.complete if verdict else False, "rebuilt_from_rerun": rebuilt}
        seal = _write_stage(run_dir, STAGE_REPORT, params, build)
        ran.append(STAGE_REPORT)
        return seal

    def _investigation_and_report(self, run_dir: Path, inputs: CaseInputs, telemetry: Telemetry,
                                  seed_seal: dict, seed: dict, ran: list) -> tuple[dict | None, dict | None, dict | None]:
        """Stages 03 and 04, computed together from one live state. Returns the two
        seals, or ``(None, None, attempt)`` when the RAM guard blocked the case."""
        params = {"previous": seed_seal["stage_sha256"], "engine": self.engine,
                  "profile": self.profile.to_dict(), "profile_sha256": self.profile.sha256(),
                  "model": self.model_identity()}
        investigation = _open_stage(run_dir, STAGE_INVESTIGATION, params)
        if investigation is not None:
            report_seal = _open_stage(run_dir, STAGE_REPORT, {"previous": investigation["stage_sha256"]})
            if report_seal is not None:
                return investigation, report_seal, None
            if self.engine != "deterministic":
                raise WorkflowRefused(
                    f"{STAGE_REPORT} is missing but {STAGE_INVESTIGATION} is sealed. A d1 investigation "
                    "cannot be replayed, and a report from a fresh run would describe a different "
                    "investigation than the sealed one. Choose a new run directory.")
            sealed = _read_json(Path(run_dir) / STAGE_INVESTIGATION / "state.json")
            row, report, _ = self._investigate(inputs, telemetry, seed)
            if strip_volatile(row["state"]) != strip_volatile(sealed["state"]):
                raise WorkflowRefused(
                    f"the deterministic re-run no longer reproduces the sealed {STAGE_INVESTIGATION}; "
                    "the report cannot be rebuilt from it. Choose a new run directory.")
            rebuilt = {"reason": f"{STAGE_REPORT} was missing; the deterministic investigation was re-run",
                       "state_matched_except": sorted(VOLATILE_KEYS),
                       "note": "report timestamps and elapsed time are the re-run's"}
            return investigation, self._write_report(run_dir, investigation, report, rebuilt, ran), None
        if (Path(run_dir) / STAGE_REPORT).exists():
            raise WorkflowRefused(f"{STAGE_REPORT} exists without {STAGE_INVESTIGATION}; the run directory "
                                  "is inconsistent. Choose a new run directory.")
        guard = None
        if self.session is not None:
            guard = self.session.guard()
            if self.session.blocks(guard):
                return None, None, _record_attempt(run_dir, BLOCKED, guard)
            self.session.ensure_loaded()
        row, report, triage = self._investigate(inputs, telemetry, seed)
        state = row["state"]
        operational = state["investigation"]["operational"]

        def build(directory):
            pilot.write_new(directory / "state.json", {
                "state": state, "operational": operational,
                "verdict_inputs": {
                    "engine": self.engine, "decision": row["scores"]["decision"],
                    "complete": row["scores"]["complete"], "triage_disposition": triage,
                    "model_disposition": operational.get("model_disposition"),
                    "rule": ("deterministic: triage of the seed findings" if self.engine == "deterministic"
                             else "d1: the model's disposition") + "; abstain whenever execution is incomplete"},
                "scripted": row["scripted"],
                "session": self.session.load_record if self.session is not None else None,
                "ram_guard": guard})
            return {"decision": row["scores"]["decision"], "complete": row["scores"]["complete"],
                    "outcome": operational["outcome"]}
        investigation = _write_stage(run_dir, STAGE_INVESTIGATION, params, build)
        ran.append(STAGE_INVESTIGATION)
        return investigation, self._write_report(run_dir, investigation, report, None, ran), None

    # -- one case -------------------------------------------------------------------

    def run_case(self, run_dir: Path, inputs: CaseInputs) -> dict:
        """Run or resume one case. Returns its outcome; ``status`` is ``complete``,
        ``blocked``, or the seed's not-investigable status."""
        run_dir = Path(run_dir)
        completed = run_dir / RUN
        if completed.exists():
            missing = [name for name in _read_json(completed).get("stages", {}) if not (run_dir / name).exists()]
            if missing:
                raise WorkflowRefused(
                    f"{RUN} records a completed run but {', '.join(missing)} is missing. A completed "
                    "run is never partly rebuilt; choose a new run directory.")
        ran: list[str] = []
        telemetry_seal, telemetry = self._telemetry(run_dir, inputs, ran)
        seed_seal, seed = self._seed(run_dir, inputs, telemetry, telemetry_seal, ran)
        seals = {STAGE_TELEMETRY: telemetry_seal, STAGE_SEED: seed_seal}
        investigation = None
        if seed["status"] == real.INVESTIGABLE:
            investigation, report_seal, attempt = self._investigation_and_report(
                run_dir, inputs, telemetry, seed_seal, seed, ran)
            if attempt is not None:
                return {"key": inputs.key, "status": BLOCKED, "run_dir": str(run_dir), "stages_run": ran,
                        "attempt": attempt, "expected": inputs.expected_decision}
            seals.update({STAGE_INVESTIGATION: investigation, STAGE_REPORT: report_seal})
        record = self._run_record(run_dir, inputs, seals, seed, investigation)
        return {"key": inputs.key, "status": record["status"], "run_dir": str(run_dir), "stages_run": ran,
                "verdict": record["verdict"], "expected": inputs.expected_decision,
                "scoring": record.get("scoring")}

    def _run_record(self, run_dir: Path, inputs: CaseInputs, seals: dict, seed: dict,
                    investigation: dict | None) -> dict:
        stages = {name: seal["stage_sha256"] for name, seal in seals.items()}
        path = run_dir / RUN
        if path.exists():
            record = _read_json(path)
            body = {k: v for k, v in record.items() if k != "run_sha256"}
            if sha256_json(body) != record.get("run_sha256") or record.get("stages") != stages:
                raise WorkflowRefused(f"{RUN} was altered or names different stages. Choose a new run directory.")
            return record
        verdict = None
        if investigation is not None:
            report = _read_json(run_dir / STAGE_REPORT / "report.json")
            state = _read_json(run_dir / STAGE_INVESTIGATION / "state.json")
            verdict = {"disposition": (report["verdict"] or {}).get("disposition", "Incomplete"),
                       "complete": bool((report["verdict"] or {}).get("complete")),
                       **state["verdict_inputs"], "title": report.get("title"),
                       "elapsed_seconds": report.get("elapsed_seconds")}
        session = _read_json(run_dir / STAGE_INVESTIGATION / "state.json")["session"] if investigation else None
        body = {"workflow": VERSION, "key": inputs.key,
                "status": COMPLETE if investigation is not None else seed["status"],
                "inputs": inputs.to_dict(), "engine": self.engine,
                "profile": self.profile.to_dict(), "profile_sha256": self.profile.sha256(),
                "model": self.model_identity(), "scripted": bool(self.session and self.session.scripted),
                "load_seconds": (session or {}).get("load_seconds"), "session": session,
                "source_sha256": self.source_sha256, "stages": stages, "verdict": verdict,
                "limits": ("Not an evaluator: expected labels are shown for scoring only; follow-up "
                           "evidence and links are not scored here.")}
        if inputs.expected_decision is not None and verdict is not None:
            body["scoring"] = {"expected_decision": inputs.expected_decision,
                               "correct": verdict["complete"] and verdict["decision"] == inputs.expected_decision,
                               "scoring_only": True}
        record = {**body, "run_sha256": sha256_json(body)}
        pilot.write_new(path, record)
        return record

    # -- batch ----------------------------------------------------------------------

    def run_batch(self, spec_path: Path, out: Path) -> dict:
        """Every spec case in ``out/cases/<key>``; completed cases are validated and
        reused. Writes ``INDEX.json`` and ``index.html`` (derived; rewritten each time)."""
        spec_path = Path(spec_path)
        spec = real.load_spec(spec_path)
        seed_mode = spec.get("seed_mode", real.DETECTION)
        out = Path(out)
        outcomes = []
        for spec_case in spec["cases"]:
            inputs = CaseInputs.from_spec(spec_case, spec_path.parent, seed_mode)
            outcome = self.run_case(out / "cases" / inputs.key, inputs)
            outcomes.append(outcome)
            print(json.dumps({k: outcome.get(k) for k in ("key", "status", "stages_run")}), flush=True)
        counts: dict[str, int] = {}
        for outcome in outcomes:
            counts[outcome["status"]] = counts.get(outcome["status"], 0) + 1
        index = {"workflow": VERSION, "spec": str(spec_path), "spec_sha256": _file_sha256(spec_path),
                 "seed_mode": seed_mode, "engine": self.engine, "profile": self.profile_version,
                 "model": self.model_identity(), "scripted": bool(self.session and self.session.scripted),
                 "model_loads_this_invocation": self.session.loads if self.session else 0,
                 "session": self.session.load_record if self.session else None,
                 "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "counts": counts, "cases": outcomes}
        _replace_text(out / INDEX, json.dumps(index, indent=2) + "\n")
        _replace_text(out / "index.html", render_index(
            [_index_entry(o) for o in outcomes], title=f"Workflow: {spec.get('name', spec_path.stem)}"))
        return index


def seed_case(telemetry: Telemetry, inputs: CaseInputs) -> dict:
    """The seed stage's record: which incident is investigated, or why none is."""
    resolved = resolve_refs(inputs.anchor_refs, telemetry)
    anchor_ids = sorted({r.event_id for r in resolved.values()} - {""})
    refs = {ref: {"status": r.status, "event_ids": list(r.event_ids)} for ref, r in resolved.items()}
    if inputs.anchor_refs:
        detection_status, incident, hunt, cases = real.select_incident(telemetry, anchor_ids)
    else:  # detection with no anchor: the slice itself must hold exactly one incident
        hunt = run_hunt(telemetry)
        cases = correlate(hunt.findings, telemetry)
        detection_status = (real.INVESTIGABLE if len(cases) == 1 else
                            real.UNDETECTED if not cases else real.AMBIGUOUS)
        incident = cases[0] if len(cases) == 1 else None
    status = detection_status
    if inputs.seed_mode == real.ANALYST:
        incident = real.analyst_incident(telemetry, anchor_ids) if len(anchor_ids) == 1 else None
        status = real.INVESTIGABLE if incident else real.UNRESOLVED_LABELS
    return {
        "seed_mode": inputs.seed_mode, "evaluation": real.protocol_for(inputs.seed_mode)["evaluation"],
        "seed_policy": real.SEED_POLICY if inputs.seed_mode == real.ANALYST else None,
        "status": status, "detection_status": detection_status, "refs": refs, "anchor_ids": anchor_ids,
        "case_id": incident.case_id if incident else None,
        "case_ids": list(incident.event_ids) if incident else [],
        "rule_ids": sorted(incident.rule_ids) if incident else [],
        "seed_findings": [_finding(f) for f in incident.findings] if incident else [],
        "detection": {"findings": [_finding(f) for f in hunt.findings],
                      "correlated_incidents": [{"case_id": c.case_id, "events": len(c.event_ids),
                                                "rule_ids": sorted(c.rule_ids)} for c in cases]},
    }


def _finding(finding) -> dict:
    return {"finding_id": finding.finding_id, "rule_id": finding.rule_id, "title": finding.title,
            "severity": finding.severity.value, "device": finding.device, "user": finding.user,
            "evidence_ids": [e.event_id for e in finding.evidence]}


def _record_attempt(run_dir: Path, status: str, guard: dict) -> dict:
    directory = Path(run_dir) / ATTEMPTS
    number = len(list(directory.glob("attempt-*.json"))) + 1 if directory.exists() else 1
    record = {"attempt": number, "status": status, "reason": "RAM guard" if guard.get("ok") is False
              else "RAM guard could not decide", "ram_guard": guard, "host_memory": pilot.host_memory(),
              "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    path = directory / f"attempt-{number}.json"
    pilot.write_new(path, record)
    return {**record, "path": path.relative_to(run_dir).as_posix()}


def _replace_text(path: Path, text: str) -> None:
    """Derived files only (the batch index): atomic replace, never a stage artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".partial")
    partial.write_text(text, encoding="utf-8")
    os.replace(partial, path)


def _index_entry(outcome: dict) -> IndexEntry:
    key = outcome["key"]
    if outcome["status"] == COMPLETE:
        verdict = outcome["verdict"]
        return IndexEntry(label=key, href=f"cases/{key}/{STAGE_REPORT}/report.html",
                          verdict=verdict["disposition"], complete=verdict["complete"],
                          elapsed_seconds=verdict.get("elapsed_seconds"), expected=outcome.get("expected"),
                          title=verdict.get("title") or "")
    if outcome["status"] == BLOCKED:
        return IndexEntry(label=key, href=f"cases/{key}/{outcome['attempt']['path']}", verdict="Blocked",
                          complete=False, expected=outcome.get("expected"),
                          title=f"Not run: {outcome['attempt']['reason']}")
    return IndexEntry(label=key, href=f"cases/{key}/{STAGE_SEED}/seed.json", verdict="Not investigated",
                      complete=False, expected=outcome.get("expected"),
                      title=f"Seed status: {outcome['status']}")
